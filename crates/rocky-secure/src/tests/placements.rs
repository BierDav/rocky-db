//! Signed header placements: a node that cannot hold a scope learns where a
//! seal's positions in it lie from their signed headers alone, and finalizes
//! and compacts the seal.
use super::compaction::{Replica, follow_main, insert, scalar, seal, sync};
use super::generations::{Lineage, identity_insert, session};
use super::*;
use crate::{PlacementPage, PlacementRequest};
use std::collections::BTreeSet;
mod conflicts;

#[tokio::test]
async fn placement_pages_bound_renewed_chains_and_continue_in_author_order() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let alice_key = PrivateKey::new();
    let bob_key = PrivateKey::new();
    let alice = lineage
        .open(&dir.path().join("alice.db"), &alice_key, 3, None)
        .await
        .unwrap();
    let bob = lineage
        .open_scoped(&dir.path().join("bob.db"), &bob_key, false, &["items"])
        .await
        .unwrap();
    follow_main(&lineage, &alice).await;
    let template = lineage.credentials(3, &alice_key);
    let user = PrivateKey::from_bytes(&rocky_core::commitment(
        "lineage.user",
        alice_key.public_key().as_bytes(),
    ));
    for index in 0..64 {
        let mut root = template.0[0].capability.clone();
        let mut node = template.0[1].capability.clone();
        root.expires -= index;
        node.expires -= index;
        alice
            .renew_credentials(CredentialChain(vec![
                SignedCapability::sign(root, lineage.publisher()).unwrap(),
                SignedCapability::sign(node, &user).unwrap(),
            ]))
            .await
            .unwrap();
        identity_insert(
            &session(&alice).await,
            &format!("INSERT INTO tags(key,label) VALUES('t{index}','tag')"),
            vec![],
        )
        .await
        .unwrap();
    }
    seal(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &bob, lineage.domain).await;
    let credentials = chain(&bob).await;
    let mut pages = 0;
    let mut stored = 0;
    while let Some(request) = bob.wanted_placements().await.unwrap().first().copied() {
        assert!(pages < 64, "placement pagination stopped making progress");
        let page = alice
            .placement_page(
                bob_key.public_key(),
                &credentials,
                &BTreeSet::new(),
                request,
            )
            .await
            .unwrap();
        assert!(crate::encode(&page).unwrap().len() < MAX_SECURE_FRAME - 512);
        let count = bob.receive_placements(request, page).await.unwrap();
        assert!(count > 0, "the page repeated positions already received");
        stored += count;
        pages += 1;
    }
    assert_eq!(stored, 64);
    assert!(pages > 1, "renewed chains must span native messages");
    bob.finalize_path(lineage.domain).await.unwrap();
    assert!(
        bob.compaction_status(lineage.domain)
            .await
            .unwrap()
            .finalized
            .is_some()
    );
}

struct Pair {
    lineage: Lineage,
    _dir: TempDir,
    alice: Replica,
    bob: (PrivateKey, Replica),
    seal: Commitment,
}

async fn chain(replica: &Replica) -> CredentialChain {
    replica
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .credentials
        .clone()
}
/// Asks `source` for every placement `target` wants, as `target`'s session.
async fn place(source: &Replica, target: &(PrivateKey, Replica)) -> usize {
    let credentials = chain(&target.1).await;
    let mut stored = 0;
    for request in target.1.wanted_placements().await.unwrap() {
        let page = source
            .placement_page(
                target.0.public_key(),
                &credentials,
                &BTreeSet::new(),
                request,
            )
            .await
            .unwrap();
        stored += target.1.receive_placements(request, page).await.unwrap();
    }
    stored
}

/// Alice holds `items` and `tags`; bob only `items`. Alice's last frames
/// before her seal are in `tags`, so bob misses their positions.
async fn pair() -> Pair {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let alice = lineage
        .open(&dir.path().join("alice.db"), &PrivateKey::new(), 3, None)
        .await
        .unwrap();
    let bob_key = PrivateKey::new();
    let bob = lineage
        .open_scoped(&dir.path().join("bob.db"), &bob_key, false, &["items"])
        .await
        .unwrap();
    follow_main(&lineage, &alice).await;
    crate::tests::exchange_graphs(&alice, &bob, lineage.domain).await;
    bob.follow_bookmark(lineage.domain, "main").await.unwrap();
    insert(&alice, "a", "one").await;
    for key in ["t1", "t2"] {
        identity_insert(
            &session(&alice).await,
            &format!("INSERT INTO tags(key,label) VALUES('{key}','tag')"),
            vec![],
        )
        .await
        .unwrap();
    }
    let seal = seal(&lineage, &alice).await.id().unwrap();
    sync(&lineage, &alice, &bob, &bob_key).await;
    Pair {
        lineage,
        _dir: dir,
        alice,
        bob: (bob_key, bob),
        seal,
    }
}

#[tokio::test]
async fn full_role_and_an_ungranted_key_do_not_turn_placements_into_payload_custody() {
    let pair = pair().await;
    let scope = pair.lineage.scope("tags");
    let key = pair
        .alice
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .keys
        .iter()
        .find(|key| key.scope == scope)
        .unwrap()
        .clone();
    {
        // Retained crypto state is not a current custody grant.
        let mut inner = pair
            .bob
            .1
            .inner
            .lock(crate::replica::Class::Background)
            .await;
        inner.config.keys.push(key);
        assert!(inner.holds(scope).await.unwrap());
        inner.conn.execute(
            "INSERT OR IGNORE INTO secure_scope_state(scope,rows,tombstones,digest,applied) SELECT ?,0,0,zeroblob(length(digest)),0 FROM secure_scope_state LIMIT 1",
            [encode(&scope).unwrap()],
        ).await.unwrap();
    }
    assert_eq!(place(&pair.alice, &pair.bob).await, 2);
    assert_eq!(
        pair.bob
            .1
            .compact(pair.lineage.domain, 0)
            .await
            .unwrap()
            .compacted,
        Some(pair.seal)
    );
    assert_eq!(scalar(&pair.bob.1, "SELECT count(*) FROM tags").await, 0);
}

#[tokio::test]
async fn a_held_scope_requires_its_payload_even_when_its_key_is_missing() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let alice = lineage
        .open(&dir.path().join("a.db"), &PrivateKey::new(), 3, None)
        .await
        .unwrap();
    let key = PrivateKey::new();
    let bob = lineage
        .open_scoped(&dir.path().join("b.db"), &key, false, &["items"])
        .await
        .unwrap();
    follow_main(&lineage, &alice).await;
    insert(&alice, "a", "one").await;
    let seal = seal(&lineage, &alice).await.id().unwrap();
    crate::tests::exchange_graphs(&alice, &bob, lineage.domain).await;
    // The grant still requires real payloads when no opening key is available.
    let keys = std::mem::take(
        &mut bob
            .inner
            .lock(crate::replica::Class::Background)
            .await
            .config
            .keys,
    );
    let mark = alice.seal_frontier(lineage.domain, false).await.unwrap()[0];
    let request = PlacementRequest {
        seal,
        author: mark.author,
        from: 0,
        to: mark.sequence,
    };
    let credentials = chain(&bob).await;
    let page = alice
        .placement_page(key.public_key(), &credentials, &BTreeSet::new(), request)
        .await
        .unwrap();
    assert_eq!(bob.receive_placements(request, page).await.unwrap(), 0);
    assert_eq!(
        scalar(&bob, "SELECT count(*) FROM secure_placements").await,
        0
    );
    bob.inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .keys = keys;
    assert_eq!(
        bob.compact(lineage.domain, 0).await.unwrap().compacted,
        None
    );
    sync(&lineage, &alice, &bob, &key).await;
    assert_eq!(
        bob.compact(lineage.domain, 0).await.unwrap().compacted,
        Some(seal)
    );
    bob.audit(lineage.scope("items")).await.unwrap();
}

#[tokio::test]
async fn a_member_finalizes_and_compacts_a_seal_whose_tail_lies_in_a_scope_it_cannot_hold() {
    let pair = pair().await;
    let (lineage, bob) = (&pair.lineage, &pair.bob);
    let waiting = bob
        .1
        .compaction_status(lineage.domain)
        .await
        .unwrap()
        .waiting
        .unwrap_or_default();
    assert!(waiting.contains("missing frames"), "{waiting}");
    assert_eq!(
        bob.1.compact(lineage.domain, 0).await.unwrap().compacted,
        None
    );
    // Two `tags` positions are placed by their headers, without bodies.
    assert_eq!(place(&pair.alice, bob).await, 2);
    assert!(bob.1.wanted_placements().await.unwrap().is_empty());
    assert_eq!(
        bob.1.compact(lineage.domain, 0).await.unwrap().compacted,
        Some(pair.seal)
    );
    // The base folded them: nothing consults them again.
    assert_eq!(
        scalar(&bob.1, "SELECT count(*) FROM secure_placements").await,
        0
    );
    bob.1.audit(lineage.scope("items")).await.unwrap();
}

#[tokio::test]
async fn a_later_held_frame_places_gaps_before_an_older_seals_frontier() {
    let pair = pair().await;
    insert(&pair.alice, "b", "two").await;
    sync(&pair.lineage, &pair.alice, &pair.bob.1, &pair.bob.0).await;
    assert!(pair.bob.1.wanted_placements().await.unwrap().is_empty());
    assert_eq!(
        pair.bob
            .1
            .compact(pair.lineage.domain, 0)
            .await
            .unwrap()
            .compacted,
        Some(pair.seal)
    );
    assert_eq!(scalar(&pair.bob.1, "SELECT count(*) FROM items").await, 2);
    assert_eq!(scalar(&pair.bob.1, "SELECT count(*) FROM tags").await, 0);
}

#[tokio::test]
async fn forged_out_of_range_held_scope_and_revoked_placements_are_refused() {
    let pair = pair().await;
    let (alice, bob) = (&pair.alice, &pair.bob);
    let credentials = chain(&bob.1).await;
    let requests = bob.1.wanted_placements().await.unwrap();
    let [request] = requests.as_slice() else {
        panic!("{requests:?}")
    };
    let credentials = &credentials;
    let answer = |request: PlacementRequest| async move {
        alice
            .placement_page(bob.0.public_key(), credentials, &BTreeSet::new(), request)
            .await
    };
    let PlacementPage::Headers { headers, chains } = answer(*request).await.unwrap() else {
        panic!("custody")
    };
    assert_eq!(headers.len(), 2);
    // A forged signature.
    let mut forged = headers.clone();
    let last = forged[0].0.len() - 1;
    forged[0].0[last] ^= 1;
    assert!(
        bob.1
            .receive_placements(
                *request,
                PlacementPage::Headers {
                    headers: forged,
                    chains: chains.clone(),
                },
            )
            .await
            .is_err()
    );
    // Headers outside the request, and a request past the seal's frontier.
    let narrow = PlacementRequest {
        to: request.from,
        ..*request
    };
    assert!(
        bob.1
            .receive_placements(
                narrow,
                PlacementPage::Headers {
                    headers: headers.clone(),
                    chains: chains.clone(),
                },
            )
            .await
            .is_err()
    );
    let past = PlacementRequest {
        to: request.to + 1,
        ..*request
    };
    assert!(answer(past).await.is_err());
    // Without its chain a header is incomplete.
    assert!(
        bob.1
            .receive_placements(
                *request,
                PlacementPage::Headers {
                    headers: headers.clone(),
                    chains: Vec::new(),
                },
            )
            .await
            .is_err()
    );
    // A genuine signature does not authorize a different domain or row format.
    let signer = alice
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .node
        .clone();
    for wrong_domain in [true, false] {
        let mut altered: p2panda_core::Header<crate::wire::Extensions> =
            decode(&headers[0].0).unwrap();
        assert_eq!(altered.public_key, signer.public_key());
        if wrong_domain {
            altered.extensions.scope.domain.domain = rocky_core::DomainId([255; 16]);
        } else {
            altered.extensions.row_format = 0;
        }
        altered.sign(&signer);
        assert!(
            bob.1
                .receive_placements(
                    *request,
                    PlacementPage::Headers {
                        headers: vec![crate::Placement(altered.to_bytes())],
                        chains: chains.clone(),
                    }
                )
                .await
                .is_err()
        );
    }
    // A position of a scope bob holds needs the frame itself.
    let items = PlacementRequest {
        from: 0,
        to: 0,
        ..*request
    };
    let page = answer(items).await.unwrap();
    assert_eq!(bob.1.receive_placements(items, page).await.unwrap(), 0);
    assert_eq!(
        scalar(&bob.1, "SELECT count(*) FROM secure_placements").await,
        0
    );
    // A revoked requester is refused.
    let user = PrivateKey::from_bytes(&rocky_core::commitment(
        "lineage.user",
        bob.0.public_key().as_bytes(),
    ));
    let revocations = crate::tests::revoking(
        pair.lineage.publisher(),
        pair.lineage.domain.app,
        &[user.public_key()],
        &[],
    );
    alice.learn_revocations(&revocations).await.unwrap();
    assert!(answer(*request).await.is_err());
    // Nothing was stored; the genuine page still places both.
    assert_eq!(
        scalar(&bob.1, "SELECT count(*) FROM secure_placements").await,
        0
    );
    assert_eq!(
        bob.1
            .receive_placements(*request, PlacementPage::Headers { headers, chains })
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn a_placement_from_a_revoked_author_is_refused() {
    let pair = pair().await;
    let request = pair.bob.1.wanted_placements().await.unwrap()[0];
    let credentials = chain(&pair.bob.1).await;
    let page = pair
        .alice
        .placement_page(
            pair.bob.0.public_key(),
            &credentials,
            &BTreeSet::new(),
            request,
        )
        .await
        .unwrap();
    let node = pair
        .alice
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .node
        .public_key();
    let user = PrivateKey::from_bytes(&rocky_core::commitment("lineage.user", node.as_bytes()));
    let revocations = crate::tests::revoking(
        pair.lineage.publisher(),
        pair.lineage.domain.app,
        &[user.public_key()],
        &[],
    );
    pair.bob.1.learn_revocations(&revocations).await.unwrap();
    assert!(pair.bob.1.receive_placements(request, page).await.is_err());
    assert_eq!(
        scalar(&pair.bob.1, "SELECT count(*) FROM secure_placements").await,
        0
    );
}

#[tokio::test]
async fn a_frame_at_a_placed_position_replaces_it_and_another_header_is_equivocation() {
    let pair = pair().await;
    let (lineage, alice, bob) = (&pair.lineage, &pair.alice, &pair.bob);
    assert_eq!(place(alice, bob).await, 2);
    // Alice's next `items` frame takes the next position. Bob holds a
    // placement there whose header is another frame's.
    let placed: Vec<u8> = {
        let inner = bob.1.inner.lock(crate::replica::Class::Background).await;
        match crate::storage::rows(&inner.conn, "SELECT header FROM secure_placements LIMIT 1")
            .await
            .unwrap()
            .first()
            .map(Vec::as_slice)
        {
            Some([rocky_core::SqlValue::Blob(header)]) => header.clone(),
            other => panic!("{other:?}"),
        }
    };
    let header: p2panda_core::Header<crate::wire::Extensions> = decode(&placed).unwrap();
    let author = header.extensions.author.unwrap();
    let next = {
        let inner = bob.1.inner.lock(crate::replica::Class::Background).await;
        let mut highest = 0;
        for record in crate::storage::rows(&inner.conn, "SELECT header FROM secure_placements")
            .await
            .unwrap()
        {
            let [rocky_core::SqlValue::Blob(bytes)] = record.as_slice() else {
                panic!()
            };
            let header: p2panda_core::Header<crate::wire::Extensions> = decode(bytes).unwrap();
            highest = highest.max(header.extensions.author_sequence);
        }
        highest + 1
    };
    {
        let inner = bob.1.inner.lock(crate::replica::Class::Background).await;
        inner
            .conn
            .execute(
                "INSERT INTO secure_placements VALUES(?,?,?,?,?,?)",
                crate::storage::bindings(vec![
                    rocky_core::SqlValue::Blob(encode(&lineage.domain).unwrap()),
                    rocky_core::SqlValue::Integer(i64::from(author)),
                    rocky_core::SqlValue::Integer(next as i64),
                    rocky_core::SqlValue::Blob(encode(&header.extensions.scope).unwrap()),
                    rocky_core::SqlValue::Blob(header.hash().as_bytes().to_vec()),
                    rocky_core::SqlValue::Blob(placed.clone()),
                ]),
            )
            .await
            .unwrap();
    }
    insert(alice, "b", "two").await;
    sync(lineage, alice, &bob.1, &bob.0).await;
    assert_eq!(bob.1.equivocations().await.unwrap(), 1);
    assert_eq!(
        scalar(
            &bob.1,
            &format!("SELECT count(*) FROM secure_placements WHERE sequence={next}")
        )
        .await,
        0
    );
}

/// Moves every frame and void of `scope` that `source` holds to `target`.
async fn sync_scope(
    lineage: &Lineage,
    source: &Replica,
    target: &Replica,
    key: &PrivateKey,
    scope: ResourceScope,
) {
    let credentials = chain(target).await;
    source
        .admit_peer(key.public_key(), &credentials, target.followed_tip().await)
        .await
        .unwrap();
    let mut after = None;
    loop {
        let frontier = target.frontier(scope).await.unwrap();
        let page = source
            .range_page(
                key.public_key(),
                &credentials,
                &frontier,
                after,
                crate::MAX_SECURE_FRAME,
            )
            .await
            .unwrap();
        for status in target.receive_voids(&page.voids).await {
            status.unwrap();
        }
        for status in target.receive_all(page.frames).await {
            status.unwrap();
        }
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    let _ = lineage;
}
/// The author number `node` signs its frames held by `replica` with.
async fn author_number(replica: &Replica, node: PublicKey) -> u32 {
    let inner = replica.inner.lock(crate::replica::Class::Background).await;
    let records = crate::storage::rows(&inner.conn, "SELECT header FROM secure_operations")
        .await
        .unwrap();
    records
        .iter()
        .find_map(|record| {
            let [rocky_core::SqlValue::Blob(bytes)] = record.as_slice() else {
                return None;
            };
            let header: p2panda_core::Header<crate::wire::Extensions> = decode(bytes).ok()?;
            (header.public_key == node).then_some(header.extensions.author?)
        })
        .expect("a frame of the node")
}
/// Revokes the identity behind a node `lineage.open` enrolled.
fn revoking_node(lineage: &Lineage, node: PublicKey) -> RevocationSet {
    let user = PrivateKey::from_bytes(&rocky_core::commitment("lineage.user", node.as_bytes()));
    crate::tests::revoking(
        lineage.publisher(),
        lineage.domain.app,
        &[user.public_key()],
        &[],
    )
}

#[tokio::test]
async fn a_relay_omits_a_revoked_authors_placements_and_still_places_others() {
    let lineage = Lineage::new();
    let dir = TempDir::new().unwrap();
    let keys = [PrivateKey::new(), PrivateKey::new(), PrivateKey::new()];
    let relay_path = dir.path().join("relay.db");
    let alice = lineage
        .open(&dir.path().join("alice.db"), &keys[0], 3, None)
        .await
        .unwrap();
    let relay = lineage.open(&relay_path, &keys[1], 3, None).await.unwrap();
    let bob = lineage
        .open_scoped(&dir.path().join("bob.db"), &keys[2], false, &["items"])
        .await
        .unwrap();
    follow_main(&lineage, &alice).await;
    for replica in [&relay, &bob] {
        crate::tests::exchange_graphs(&alice, replica, lineage.domain).await;
        replica
            .follow_bookmark(lineage.domain, "main")
            .await
            .unwrap();
    }
    let tag = |replica, key: &'static str| async move {
        identity_insert(
            &session(replica).await,
            &format!("INSERT INTO tags(key,label) VALUES('{key}','tag')"),
            vec![],
        )
        .await
        .unwrap();
    };
    // Alice writes an item and two tags; the relay holds them all.
    insert(&alice, "a", "one").await;
    tag(&alice, "t1").await;
    tag(&alice, "t2").await;
    for name in ["items", "tags"] {
        sync_scope(&lineage, &alice, &relay, &keys[1], lineage.scope(name)).await;
    }
    // A third tag reaches the relay only as Alice's signed void.
    tag(&alice, "t3").await;
    let voided = {
        let inner = alice.inner.lock(crate::replica::Class::Background).await;
        match crate::storage::rows(
            &inner.conn,
            "SELECT header FROM secure_operations ORDER BY rowid DESC LIMIT 1",
        )
        .await
        .unwrap()
        .first()
        .map(Vec::as_slice)
        {
            Some([rocky_core::SqlValue::Blob(header)]) => header.clone(),
            other => panic!("{other:?}"),
        }
    };
    let void = crate::SignedVoid::sign(&keys[0], vec![voided]).unwrap();
    for status in relay.receive_voids(&[void]).await {
        status.unwrap();
    }
    // The relay tags too, then seals what it holds.
    tag(&relay, "r1").await;
    let sealed = seal(&lineage, &relay).await.id().unwrap();
    crate::tests::exchange_graphs(&relay, &bob, lineage.domain).await;
    sync(&lineage, &relay, &bob, &keys[2]).await;
    let alice_node = alice
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .node
        .public_key();
    let relay_node = relay
        .inner
        .lock(crate::replica::Class::Background)
        .await
        .config
        .node
        .public_key();
    let requests = bob.wanted_placements().await.unwrap();
    let (alice_author, relay_author) = (
        author_number(&alice, alice_node).await,
        author_number(&relay, relay_node).await,
    );
    let alice_request = *requests
        .iter()
        .find(|request| request.author == alice_author)
        .expect("alice's positions");
    let relay_request = *requests
        .iter()
        .find(|request| request.author == relay_author)
        .expect("the relay's positions");
    assert_eq!(alice_request.seal, sealed);
    let credentials = chain(&bob).await;
    let peer = keys[2].public_key();
    let answer = |request: PlacementRequest| {
        let (relay, credentials) = (&relay, &credentials);
        async move {
            relay
                .placement_page(peer, credentials, &BTreeSet::new(), request)
                .await
                .unwrap()
        }
    };
    let headers_of = |page: &PlacementPage| match page {
        PlacementPage::Headers { headers, chains } => (headers.len(), chains.len()),
        PlacementPage::CustodyRequired => panic!("custody"),
    };
    // Before the revocation the relay places Alice's two tags and her void,
    // and her `items` position bob holds.
    let alice_page = answer(alice_request).await;
    assert_eq!(headers_of(&alice_page), (3, 1));
    let items = PlacementRequest {
        from: 0,
        to: 0,
        ..alice_request
    };
    let items_page = answer(items).await;
    assert_eq!(headers_of(&items_page).0, 1);
    let alice_headers = format!(
        "SELECT (SELECT count(*) FROM secure_operations WHERE author=x'{0}')+(SELECT count(*) FROM secure_voids WHERE author=x'{0}')",
        alice_node
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let retained = scalar(&relay, &alice_headers).await;
    assert_eq!(retained, 4);

    relay
        .learn_revocations(&revoking_node(&lineage, alice_node))
        .await
        .unwrap();
    // Still physically held, no longer offered as evidence.
    assert_eq!(scalar(&relay, &alice_headers).await, retained);
    let omitted = answer(alice_request).await;
    assert_eq!(headers_of(&omitted), (0, 0));
    assert_eq!(headers_of(&answer(items).await), (0, 0));
    assert_eq!(
        bob.receive_placements(alice_request, omitted)
            .await
            .unwrap(),
        0
    );
    assert!(
        bob.wanted_placements()
            .await
            .unwrap()
            .contains(&alice_request)
    );
    // An unrevoked author's position still transfers.
    let relay_page = answer(relay_request).await;
    assert_eq!(headers_of(&relay_page), (1, 1));
    assert_eq!(
        bob.receive_placements(relay_request, relay_page)
            .await
            .unwrap(),
        1
    );
    // A page captured before the revocation is refused whole once bob
    // learns it, for a held scope too, and changes nothing.
    bob.learn_revocations(&revoking_node(&lineage, alice_node))
        .await
        .unwrap();
    let revision = bob.stored_and_memory_revision().await;
    let placed = scalar(&bob, "SELECT count(*) FROM secure_placements").await;
    assert!(
        bob.receive_placements(alice_request, alice_page)
            .await
            .is_err()
    );
    assert!(bob.receive_placements(items, items_page).await.is_err());
    assert_eq!(
        scalar(&bob, "SELECT count(*) FROM secure_placements").await,
        placed
    );
    assert_eq!(bob.stored_and_memory_revision().await, revision);
    // Reopened with its keys, the relay still omits them.
    drop(relay);
    let relay = lineage.reopen(&relay_path, &keys[1], 3, 3).await.unwrap();
    relay.audit(lineage.scope("items")).await.unwrap();
    relay.audit(lineage.scope("tags")).await.unwrap();
    let page = relay
        .placement_page(peer, &credentials, &BTreeSet::new(), alice_request)
        .await
        .unwrap();
    assert_eq!(headers_of(&page), (0, 0));
    assert_eq!(scalar(&relay, &alice_headers).await, retained);
}
