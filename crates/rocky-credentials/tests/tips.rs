use rocky_core::{AppId, DomainId, MeshId, PrincipalKind, Scope, TipId};
use rocky_credentials::{
    AuthorMark, AuthorRange, Authority, BOOKMARK_MOVE_FORMAT, BookmarkMoveStatement,
    CredentialChain, Extended, Extension, LogPoint, PrivateKey, Recovery, RevocationSet,
    SEAL_FORMAT, SealAction, SealStatement, SignedBookmarkMove, SignedCapability, SignedSeal,
    SignedTipOpening, TIP_OPENING_FORMAT, TipGraph, TipOpeningStatement, encode, genesis_tip,
};

fn graph() -> TipGraph {
    TipGraph::new(
        Scope {
            mesh: MeshId([1; 16]),
            app: AppId([2; 16]),
            domain: DomainId([3; 16]),
        },
        [4; 32],
    )
}
fn seal(graph: &TipGraph, tip: TipId, sequence: u64, owner: &PrivateKey) -> SignedSeal {
    SignedSeal::sign(
        SealStatement {
            format: SEAL_FORMAT,
            scope: graph.scope,
            tip,
            frontier: vec![AuthorMark {
                author: 1,
                sequence,
            }],
            action: SealAction::Continue {
                schema: graph.genesis_schema,
            },
            recovery: None,
        },
        owner,
    )
    .unwrap()
}
fn movement(
    graph: &TipGraph,
    name: &str,
    from: Option<TipId>,
    to: Option<TipId>,
    owner: &PrivateKey,
) -> SignedBookmarkMove {
    SignedBookmarkMove::sign(
        BookmarkMoveStatement {
            format: BOOKMARK_MOVE_FORMAT,
            scope: graph.scope,
            name: name.into(),
            from,
            to,
        },
        owner,
    )
    .unwrap()
}
fn opening(graph: &TipGraph, seal: &SignedSeal, owner: &PrivateKey) -> SignedTipOpening {
    SignedTipOpening::sign(
        TipOpeningStatement {
            format: TIP_OPENING_FORMAT,
            schema: graph.schema_any(seal.statement.tip).unwrap(),
            scope: graph.scope,
            seal: seal.id().unwrap(),
            minimum_in_sync: 2,
        },
        owner,
    )
    .unwrap()
}

#[test]
fn genesis_and_statement_ids_roundtrip_and_refuse_other_formats() {
    let owner = PrivateKey::new();
    let mut graph = graph();
    assert_eq!(genesis_tip(graph.genesis_schema), graph.genesis());
    assert_ne!(genesis_tip([5; 32]), graph.genesis());
    let signed = seal(&graph, graph.genesis(), 3, &owner);
    let decoded = SignedSeal::from_bytes(&signed.to_bytes().unwrap()).unwrap();
    decoded.verify(owner.public_key(), &graph).unwrap();
    assert_eq!(decoded, signed);
    assert_eq!(
        signed.successor().unwrap(),
        Some(TipId(signed.id().unwrap()))
    );
    graph.seals.push(signed.clone());
    let opened = opening(&graph, &signed, &owner);
    SignedTipOpening::from_bytes(&opened.to_bytes().unwrap())
        .unwrap()
        .verify(owner.public_key(), &graph)
        .unwrap();
    assert_eq!(opened.tip().unwrap(), TipId(opened.id().unwrap()));
    let moved = movement(&graph, "main", None, Some(graph.genesis()), &owner);
    SignedBookmarkMove::from_bytes(&moved.to_bytes().unwrap())
        .unwrap()
        .verify(owner.public_key(), &graph)
        .unwrap();
    for format in [0, 3, u32::MAX] {
        let mut other = signed.clone();
        other.statement.format = format;
        assert!(other.verify(owner.public_key(), &graph).is_err());
        assert!(SignedSeal::from_bytes(&other.to_bytes().unwrap()).is_err());
        let mut other = opened.clone();
        other.statement.format = format;
        assert!(other.verify(owner.public_key(), &graph).is_err());
        assert!(SignedTipOpening::from_bytes(&other.to_bytes().unwrap()).is_err());
        let mut other = moved.clone();
        other.statement.format = format;
        assert!(other.verify(owner.public_key(), &graph).is_err());
        assert!(SignedBookmarkMove::from_bytes(&other.to_bytes().unwrap()).is_err());
        #[derive(serde::Serialize)]
        struct Format {
            format: u32,
        }
        #[derive(serde::Serialize)]
        struct Envelope {
            statement: Format,
        }
        let bytes = encode(&Envelope {
            statement: Format { format },
        })
        .unwrap();
        assert!(SignedSeal::from_bytes(&bytes).is_err());
        assert!(SignedTipOpening::from_bytes(&bytes).is_err());
        assert!(SignedBookmarkMove::from_bytes(&bytes).is_err());
    }
    let mut tampered = signed.clone();
    tampered.statement.frontier[0].sequence += 1;
    assert!(tampered.verify(owner.public_key(), &graph).is_err());
    assert!(
        signed
            .verify(PrivateKey::new().public_key(), &graph)
            .is_err()
    );
}

#[test]
fn two_issuers_seal_concurrently_and_lower_digest_wins_in_every_order() {
    let owner = PrivateKey::new();
    let issuers = [PrivateKey::new(), PrivateKey::new()];
    let mut graph = graph();
    let mut seals = Vec::new();
    for (index, issuer) in issuers.iter().enumerate() {
        let chain = CredentialChain(vec![
            Authority::owner(&owner)
                .issue_issuer(issuer.public_key(), None, (100, 1000, 0))
                .unwrap(),
        ]);
        let signed = SignedSeal::endorse(
            seal(&graph, graph.genesis(), index as u64, &owner).statement,
            issuer,
            &chain,
        )
        .unwrap();
        signed
            .verify_current(owner.public_key(), &graph, &RevocationSet::new(), 200)
            .unwrap();
        seals.push(signed);
    }
    graph.seals = seals.clone();
    let winner = seals.iter().min_by_key(|seal| seal.id().unwrap()).unwrap();
    assert_eq!(graph.seal(graph.genesis()).unwrap(), Some(winner));
    assert_eq!(
        graph.schema(winner.successor().unwrap().unwrap()).unwrap(),
        graph.genesis_schema
    );
    let losing = seals.iter().max_by_key(|seal| seal.id().unwrap()).unwrap();
    assert!(graph.schema(losing.successor().unwrap().unwrap()).is_err());
    graph.seals.reverse();
    assert_eq!(graph.seal(graph.genesis()).unwrap(), Some(winner));
    assert_eq!(
        graph
            .line_root(winner.successor().unwrap().unwrap())
            .unwrap(),
        graph.genesis()
    );
    let losing_tip = losing.successor().unwrap().unwrap();
    let retained = seal(&graph, losing_tip, 8, &owner);
    retained.verify(owner.public_key(), &graph).unwrap();
    graph.seals.push(retained.clone());
    assert_eq!(
        graph
            .schema_any(retained.successor().unwrap().unwrap())
            .unwrap(),
        graph.genesis_schema
    );
    assert!(
        graph
            .schema(retained.successor().unwrap().unwrap())
            .is_err()
    );
    let created = movement(&graph, "main", None, Some(graph.genesis()), &owner);
    let moved = movement(
        &graph,
        "main",
        Some(graph.genesis()),
        Some(losing_tip),
        &owner,
    );
    moved.verify(owner.public_key(), &graph).unwrap();
    graph.moves = vec![created, moved];
    assert_eq!(graph.bookmark("main").unwrap(), winner.successor().unwrap());
    graph.seals.reverse();
    graph.moves.reverse();
    assert_eq!(graph.bookmark("main").unwrap(), winner.successor().unwrap());
}

#[test]
fn concurrent_bookmark_moves_and_backward_move_resolve_without_arrival_order() {
    let owner = PrivateKey::new();
    let mut graph = graph();
    let first = seal(&graph, graph.genesis(), 1, &owner);
    let second_tip = first.successor().unwrap().unwrap();
    graph.seals.push(first);
    let second = seal(&graph, second_tip, 2, &owner);
    let third_tip = second.successor().unwrap().unwrap();
    graph.seals.push(second);
    let created = movement(&graph, "main", None, Some(graph.genesis()), &owner);
    let a = movement(
        &graph,
        "main",
        Some(graph.genesis()),
        Some(second_tip),
        &owner,
    );
    let b = movement(
        &graph,
        "main",
        Some(graph.genesis()),
        Some(third_tip),
        &owner,
    );
    let expected = if a.id().unwrap() < b.id().unwrap() {
        second_tip
    } else {
        third_tip
    };
    graph.moves = vec![created, a, b];
    assert_eq!(graph.bookmark("main").unwrap(), Some(expected));
    graph.moves.reverse();
    assert_eq!(graph.bookmark("main").unwrap(), Some(expected));
    graph.moves.push(movement(
        &graph,
        "main",
        Some(expected),
        Some(graph.genesis()),
        &owner,
    ));
    assert_eq!(graph.bookmark("main").unwrap(), Some(graph.genesis()));
}

#[test]
fn issuers_move_only_forward_and_owner_controlled_trust_opens_and_moves_sideways() {
    let owner = PrivateKey::new();
    let issuer = PrivateKey::new();
    let trusted = PrivateKey::new();
    let mut graph = graph();
    let issuer_chain = CredentialChain(vec![
        Authority::owner(&owner)
            .issue_issuer(issuer.public_key(), None, (100, 1000, 0))
            .unwrap(),
    ]);
    let trusted_chain = CredentialChain(vec![
        Authority::owner(&owner)
            .issue_trusted(
                trusted.public_key(),
                graph.scope,
                Vec::new(),
                AuthorRange::ALL,
                (100, 1000, 0),
            )
            .unwrap(),
    ]);
    let first = seal(&graph, graph.genesis(), 1, &owner);
    let next = first.successor().unwrap().unwrap();
    graph.seals.push(first.clone());
    let opened = SignedTipOpening::endorse(
        opening(&graph, &first, &owner).statement,
        &trusted,
        &trusted_chain,
    )
    .unwrap();
    opened
        .verify_current(owner.public_key(), &graph, &RevocationSet::new(), 200)
        .unwrap();
    let branch = opened.tip().unwrap();
    graph.openings.push(opened.clone());
    assert_eq!(graph.line_root(branch).unwrap(), branch);
    assert!(!graph.continues(next, branch).unwrap());
    assert!(
        SignedTipOpening::endorse(opened.statement, &issuer, &issuer_chain)
            .unwrap()
            .verify(owner.public_key(), &graph)
            .is_err()
    );
    for (from, to, allowed) in [
        (Some(graph.genesis()), Some(next), true),
        (None, Some(next), false),
        (Some(next), None, false),
        (Some(next), Some(graph.genesis()), false),
        (Some(next), Some(branch), false),
    ] {
        let statement = movement(&graph, "main", from, to, &owner).statement;
        let signed =
            SignedBookmarkMove::endorse(statement.clone(), &issuer, &issuer_chain).unwrap();
        assert_eq!(
            signed
                .verify_current(owner.public_key(), &graph, &RevocationSet::new(), 200)
                .is_ok(),
            allowed
        );
        SignedBookmarkMove::endorse(statement, &trusted, &trusted_chain)
            .unwrap()
            .verify_current(owner.public_key(), &graph, &RevocationSet::new(), 200)
            .unwrap();
    }
    assert!(
        Authority::issuer(&issuer, &issuer_chain)
            .issue_trusted(
                trusted.public_key(),
                graph.scope,
                Vec::new(),
                AuthorRange::ALL,
                (100, 1000, 0)
            )
            .is_err()
    );
    let forged = SignedCapability::sign(trusted_chain.0[0].capability.clone(), &issuer).unwrap();
    let forged_chain = CredentialChain(vec![issuer_chain.0[0].clone(), forged]);
    assert!(
        SignedTipOpening::endorse(
            opening(&graph, &first, &owner).statement,
            &trusted,
            &forged_chain
        )
        .unwrap()
        .verify(owner.public_key(), &graph)
        .is_err()
    );
    assert!(
        SignedTipOpening::endorse(
            opening(&graph, &first, &owner).statement,
            &trusted,
            &trusted_chain
        )
        .unwrap()
        .verify_current(owner.public_key(), &graph, &RevocationSet::new(), 1200)
        .is_err()
    );
    let mut other = graph.clone();
    other.scope.domain = DomainId([7; 16]);
    let wrong = SignedSeal::endorse(
        seal(&other, other.genesis(), 0, &owner).statement,
        &trusted,
        &trusted_chain,
    )
    .unwrap();
    assert!(wrong.verify(owner.public_key(), &other).is_err());
}

#[test]
fn schema_changes_are_allowed_but_partial_and_node_authority_and_invalid_frontiers_are_refused() {
    let owner = PrivateKey::new();
    let user = PrivateKey::new();
    let graph = graph();
    let mut statement = seal(&graph, graph.genesis(), 1, &owner).statement;
    statement.action = SealAction::Continue { schema: [8; 32] };
    SignedSeal::sign(statement.clone(), &owner)
        .unwrap()
        .verify(owner.public_key(), &graph)
        .unwrap();
    statement.action = SealAction::Close;
    SignedSeal::sign(statement.clone(), &owner)
        .unwrap()
        .verify(owner.public_key(), &graph)
        .unwrap();
    for frontier in [
        vec![AuthorMark {
            author: 0,
            sequence: 1,
        }],
        vec![AuthorMark {
            author: 1,
            sequence: u64::MAX,
        }],
        vec![
            AuthorMark {
                author: 2,
                sequence: 1,
            },
            AuthorMark {
                author: 1,
                sequence: 1,
            },
        ],
        vec![
            AuthorMark {
                author: 1,
                sequence: 1
            };
            2
        ],
    ] {
        statement.frontier = frontier;
        assert!(SignedSeal::sign(statement.clone(), &owner).is_err());
    }
    let capability = rocky_credentials::Capability {
        subject: user.public_key(),
        kind: PrincipalKind::User,
        grants: vec![rocky_core::ResourceGrant {
            scope: rocky_core::ResourceScope {
                domain: graph.scope,
                table: [9; 32],
                encryption: [8; 32],
            },
            rows: rocky_core::RowSelection::All,
            fields: rocky_core::FieldSelection::All,
            rights: [rocky_core::Right::Read].into(),
        }],
        not_before: 100,
        expires: 1000,
        delegations: 1,
        extension: Extension::new(Extended {
            authors: Some(AuthorRange::ALL),
            ..Default::default()
        })
        .unwrap(),
    };
    let chain = CredentialChain(vec![SignedCapability::sign(capability, &owner).unwrap()]);
    assert!(
        SignedSeal::endorse(
            seal(&graph, graph.genesis(), 1, &owner).statement,
            &user,
            &chain
        )
        .unwrap()
        .verify(owner.public_key(), &graph)
        .is_err()
    );
}

#[test]
fn node_signatures_never_inherit_trusted_identity_control() {
    let owner = PrivateKey::new();
    let identity = PrivateKey::new();
    let node = PrivateKey::new();
    let graph = graph();
    let root = Authority::owner(&owner)
        .issue_trusted(
            identity.public_key(),
            graph.scope,
            vec![rocky_core::ResourceGrant {
                scope: rocky_core::ResourceScope {
                    domain: graph.scope,
                    table: [9; 32],
                    encryption: [8; 32],
                },
                rows: rocky_core::RowSelection::All,
                fields: rocky_core::FieldSelection::All,
                rights: [rocky_core::Right::Read].into(),
            }],
            AuthorRange::ALL,
            (100, 1000, 0),
        )
        .unwrap();
    let chain = rocky_credentials::device_chain(root, &identity, node.public_key(), 1).unwrap();
    chain
        .verify(
            owner.public_key(),
            node.public_key(),
            &RevocationSet::new(),
            200,
        )
        .unwrap();
    assert_eq!(
        chain
            .0
            .last()
            .unwrap()
            .capability
            .extended()
            .unwrap()
            .trusted,
        None
    );
    assert!(
        SignedSeal::endorse(
            seal(&graph, graph.genesis(), 1, &owner).statement,
            &node,
            &chain
        )
        .unwrap()
        .verify(owner.public_key(), &graph)
        .is_err()
    );
}

/// An issuer's chain, issued by the owner.
fn issuer_chain(owner: &PrivateKey, issuer: &PrivateKey) -> CredentialChain {
    CredentialChain(vec![
        Authority::owner(owner)
            .issue_issuer(issuer.public_key(), None, (100, 1000, 0))
            .unwrap(),
    ])
}
fn trusted_chain(graph: &TipGraph, owner: &PrivateKey, trusted: &PrivateKey) -> CredentialChain {
    CredentialChain(vec![
        Authority::owner(owner)
            .issue_trusted(
                trusted.public_key(),
                graph.scope,
                Vec::new(),
                AuthorRange::new(5, 5).unwrap(),
                (100, 1000, 0),
            )
            .unwrap(),
    ])
}
/// One seal of `tip` per signer, varied by `sequence` so their digests differ.
fn endorsed(
    graph: &TipGraph,
    owner: &PrivateKey,
    tip: TipId,
    sequence: u64,
    signer: &PrivateKey,
    chain: &CredentialChain,
) -> SignedSeal {
    let signed =
        SignedSeal::endorse(seal(graph, tip, sequence, owner).statement, signer, chain).unwrap();
    signed
        .verify_current(owner.public_key(), graph, &RevocationSet::new(), 200)
        .unwrap();
    signed
}
fn revoking(owner: &PrivateKey, identities: &[rocky_credentials::PublicKey]) -> RevocationSet {
    let statement = rocky_credentials::Revocation {
        app: graph().scope.app,
        issuer: owner.public_key(),
        time: 200,
        nodes: Default::default(),
        identities: identities.iter().copied().collect(),
        capabilities: Default::default(),
    };
    let signed = Authority::owner(owner).revoke(statement).unwrap();
    RevocationSet::try_from(vec![signed]).unwrap()
}

#[test]
fn seals_resolve_by_authority_before_digest_and_revocation_resolves_again() {
    let owner = PrivateKey::new();
    let (issuer, other, trusted) = (PrivateKey::new(), PrivateKey::new(), PrivateKey::new());
    let mut graph = graph();
    let tip = graph.genesis();
    let issuers: Vec<_> = (0..8)
        .map(|sequence| {
            let signer = if sequence % 2 == 0 { &issuer } else { &other };
            endorsed(
                &graph,
                &owner,
                tip,
                sequence,
                signer,
                &issuer_chain(&owner, signer),
            )
        })
        .collect();
    let trusted_seal = endorsed(
        &graph,
        &owner,
        tip,
        20,
        &trusted,
        &trusted_chain(&graph, &owner, &trusted),
    );
    let owner_seal = seal(&graph, tip, 30, &owner);
    let authority = |seal: &SignedSeal| graph.authority(seal.endorsement());
    assert_eq!(
        authority(&issuers[0]),
        rocky_credentials::TipAuthority::Issuer
    );
    assert_eq!(
        authority(&trusted_seal),
        rocky_credentials::TipAuthority::Trusted
    );
    assert_eq!(
        authority(&owner_seal),
        rocky_credentials::TipAuthority::Owner
    );

    // Among issuers the lower digest wins; any trusted seal beats them and
    // the owner's beats all, whatever the digests and in every order.
    graph.seals = issuers.clone();
    let lowest = issuers
        .iter()
        .min_by_key(|seal| seal.id().unwrap())
        .unwrap()
        .clone();
    assert_eq!(graph.seal(tip).unwrap(), Some(&lowest));
    graph.seals.push(trusted_seal.clone());
    assert_eq!(graph.seal(tip).unwrap(), Some(&trusted_seal));
    graph.seals.insert(0, owner_seal.clone());
    assert_eq!(graph.seal(tip).unwrap(), Some(&owner_seal));
    graph.seals.reverse();
    assert_eq!(graph.seal(tip).unwrap(), Some(&owner_seal));
    assert!(
        graph
            .schema(trusted_seal.successor().unwrap().unwrap())
            .is_err()
    );

    // Revoking the issuer whose seal won among issuers hands the race to
    // the other issuer's best seal; the owner's statements are never left out.
    graph.seals = issuers.clone();
    let winner_signer = if issuers.iter().position(|seal| *seal == lowest).unwrap() % 2 == 0 {
        &issuer
    } else {
        &other
    };
    let revocations = revoking(&owner, &[winner_signer.public_key()]);
    assert!(graph.exclude_revoked(&revocations).unwrap());
    assert!(!graph.exclude_revoked(&revocations).unwrap());
    let next = issuers
        .iter()
        .filter(|seal| !graph.revoked.contains(&seal.id().unwrap()))
        .min_by_key(|seal| seal.id().unwrap())
        .unwrap();
    assert_ne!(next, &lowest);
    assert_eq!(graph.seal(tip).unwrap(), Some(next));
    assert_eq!(graph.revoked.len(), 4);
    graph.seals.push(owner_seal.clone());
    assert!(!graph.exclude_revoked(&revocations).unwrap());
    assert!(!graph.revoked.contains(&owner_seal.id().unwrap()));
    assert_eq!(graph.seal(tip).unwrap(), Some(&owner_seal));
}

#[test]
fn an_owners_backward_move_beats_an_issuers_forward_move_and_the_loser_is_listed() {
    let owner = PrivateKey::new();
    let issuer = PrivateKey::new();
    let chain = issuer_chain(&owner, &issuer);
    let mut graph = graph();
    let first = seal(&graph, graph.genesis(), 1, &owner);
    let main_tip = first.successor().unwrap().unwrap();
    graph.seals.push(first);
    graph.moves = vec![
        movement(&graph, "main", None, Some(graph.genesis()), &owner),
        movement(
            &graph,
            "main",
            Some(graph.genesis()),
            Some(main_tip),
            &owner,
        ),
    ];
    // Concurrently: an issuer seals main's tip and moves main forward; the
    // owner closes it and moves main back to genesis.
    let forward_seal = endorsed(&graph, &owner, main_tip, 2, &issuer, &chain);
    let forward_tip = forward_seal.successor().unwrap().unwrap();
    let mut close = seal(&graph, main_tip, 3, &owner);
    close.statement.action = SealAction::Close;
    let close = SignedSeal::sign(close.statement, &owner).unwrap();
    graph.seals.push(forward_seal.clone());
    let forward = SignedBookmarkMove::endorse(
        movement(&graph, "main", Some(main_tip), Some(forward_tip), &owner).statement,
        &issuer,
        &chain,
    )
    .unwrap();
    graph.seals.push(close.clone());
    let back = movement(
        &graph,
        "main",
        Some(main_tip),
        Some(graph.genesis()),
        &owner,
    );
    for order in [false, true] {
        graph.moves.truncate(2);
        if order {
            graph.moves.extend([forward.clone(), back.clone()]);
        } else {
            graph.moves.extend([back.clone(), forward.clone()]);
        }
        assert_eq!(graph.seal(main_tip).unwrap(), Some(&close));
        assert_eq!(graph.bookmark("main").unwrap(), Some(graph.genesis()));
        assert_eq!(graph.losing_moves("main").unwrap(), vec![&forward]);
    }
    // Revoking the owner's rival changes nothing here; the loser is no
    // longer listed once revoked.
    assert!(
        graph
            .exclude_revoked(&revoking(&owner, &[issuer.public_key()]))
            .unwrap()
    );
    assert_eq!(graph.bookmark("main").unwrap(), Some(graph.genesis()));
    assert!(graph.losing_moves("main").unwrap().is_empty());
}

/// A node of a fresh trusted identity, with its two-link chain.
fn trusted_node(graph: &TipGraph, owner: &PrivateKey) -> (PrivateKey, CredentialChain) {
    let identity = PrivateKey::new();
    let node = PrivateKey::new();
    let root = Authority::owner(owner)
        .issue_trusted(
            identity.public_key(),
            graph.scope,
            vec![rocky_core::ResourceGrant {
                scope: rocky_core::ResourceScope {
                    domain: graph.scope,
                    table: [9; 32],
                    encryption: [8; 32],
                },
                rows: rocky_core::RowSelection::All,
                fields: rocky_core::FieldSelection::All,
                rights: [rocky_core::Right::Read].into(),
            }],
            AuthorRange::ALL,
            (100, 1000, 0),
        )
        .unwrap();
    let chain = rocky_credentials::device_chain(root, &identity, node.public_key(), 1).unwrap();
    (node, chain)
}
fn ack(
    graph: &TipGraph,
    seal: &SignedSeal,
    (node, chain): &(PrivateKey, CredentialChain),
) -> rocky_credentials::TerminalAck {
    rocky_credentials::TerminalAck::sign(
        rocky_credentials::TerminalAckStatement {
            format: rocky_credentials::TERMINAL_ACK_FORMAT,
            scope: graph.scope,
            tip: seal.statement.tip,
            position: 4,
            running: [9; 32],
            seal: seal.id().unwrap(),
            continuation: seal.successor().unwrap(),
        },
        node,
        chain.clone(),
    )
    .unwrap()
}

#[test]
fn a_final_seal_beats_the_owners_and_revoking_its_acknowledgers_resolves_again() {
    let owner = PrivateKey::new();
    let issuer = PrivateKey::new();
    let mut graph = graph();
    let tip = graph.genesis();
    let committed = endorsed(
        &graph,
        &owner,
        tip,
        1,
        &issuer,
        &issuer_chain(&owner, &issuer),
    );
    let owner_seal = seal(&graph, tip, 2, &owner);
    graph.seals = vec![committed.clone(), owner_seal.clone()];
    assert_eq!(graph.seal(tip).unwrap(), Some(&owner_seal));

    let nodes = [trusted_node(&graph, &owner), trusted_node(&graph, &owner)];
    let record = rocky_credentials::SealFinality::new(
        graph.scope,
        committed.id().unwrap(),
        nodes
            .iter()
            .map(|node| ack(&graph, &committed, node))
            .collect(),
    );
    let current = RevocationSet::new();
    // Without the owner's signed minimum the genesis line has no final seal.
    assert!(
        graph
            .verify_finality(&record, owner.public_key(), Some((&current, 200)))
            .is_err()
    );
    let line = |minimum| {
        rocky_credentials::SignedGenesisLine::sign(
            rocky_credentials::GenesisLineStatement {
                format: rocky_credentials::GENESIS_LINE_FORMAT,
                scope: graph.scope,
                minimum_in_sync: minimum,
            },
            &owner,
        )
        .unwrap()
    };
    graph.genesis_lines.push(line(3));
    assert!(
        graph
            .verify_finality(&record, owner.public_key(), Some((&current, 200)))
            .is_err()
    );
    graph.genesis_lines = vec![line(2)];
    graph
        .verify_finality(&record, owner.public_key(), Some((&current, 200)))
        .unwrap();
    // An issuer cannot sign the genesis line's minimum.
    assert!(
        rocky_credentials::SignedGenesisLine::endorse(
            line(1).statement,
            &issuer,
            &issuer_chain(&owner, &issuer)
        )
        .unwrap()
        .verify(owner.public_key(), &graph)
        .is_err()
    );
    // Acknowledgments of another seal do not make this one final.
    let mut forged = record.clone();
    forged.seal = owner_seal.id().unwrap();
    assert!(
        graph
            .verify_finality(&forged, owner.public_key(), Some((&current, 200)))
            .is_err()
    );

    graph.finalities.push(record.clone());
    assert!(graph.is_final(committed.id().unwrap()).unwrap());
    assert_eq!(graph.seal(tip).unwrap(), Some(&committed));
    assert_eq!(
        graph
            .canonical_tip(committed.successor().unwrap().unwrap())
            .unwrap(),
        committed.successor().unwrap().unwrap()
    );
    assert_eq!(
        graph
            .canonical_tip(owner_seal.successor().unwrap().unwrap())
            .unwrap(),
        committed.successor().unwrap().unwrap()
    );

    // Revoking one acknowledger's identity leaves the record below the
    // minimum: the owner's seal wins again.
    let identity = nodes[0].1.0[0].capability.subject;
    assert!(
        graph
            .exclude_revoked(&revoking(&owner, &[identity]))
            .unwrap()
    );
    assert!(!graph.is_final(committed.id().unwrap()).unwrap());
    assert_eq!(graph.seal(tip).unwrap(), Some(&owner_seal));
    for seal in [&committed, &owner_seal] {
        assert_eq!(
            graph
                .canonical_tip(seal.successor().unwrap().unwrap())
                .unwrap(),
            owner_seal.successor().unwrap().unwrap()
        );
    }
}

#[test]
fn checkpoint_records_name_a_held_seal_and_revocation_unlists_them() {
    use rocky_credentials::{
        CHECKPOINT_RECORD_FORMAT, CheckpointRecordStatement, SignedCheckpointRecord,
    };
    let owner = PrivateKey::new();
    let issuer = PrivateKey::new();
    let mut graph = graph();
    let sealed = seal(&graph, graph.genesis(), 3, &owner);
    let statement = |seal: &SignedSeal, rows: u64| CheckpointRecordStatement {
        format: CHECKPOINT_RECORD_FORMAT,
        scope: graph.scope,
        seal: seal.id().unwrap(),
        table: rocky_core::ResourceScope {
            domain: graph.scope,
            encryption: [6; 32],
            table: [7; 32],
        },
        checkpoint: [8; 32],
        signer: PrivateKey::new().public_key(),
        rows,
    };
    let record = SignedCheckpointRecord::endorse(
        statement(&sealed, 4),
        &issuer,
        &issuer_chain(&owner, &issuer),
    )
    .unwrap();
    // A record of a seal the graph does not hold, or of another domain, is refused.
    let current = |record: &SignedCheckpointRecord, graph: &TipGraph| {
        record.verify_current(owner.public_key(), graph, &RevocationSet::new(), 200)
    };
    assert!(current(&record, &graph).is_err());
    graph.seals.push(sealed.clone());
    current(&record, &graph).unwrap();
    let mut other = statement(&sealed, 4);
    other.table.domain.domain = DomainId([9; 16]);
    assert!(SignedCheckpointRecord::sign(other, &owner).is_err());
    let decoded = SignedCheckpointRecord::from_bytes(&record.to_bytes().unwrap()).unwrap();
    assert_eq!(decoded, record);

    // Inspection lists it at its seal until its issuer is revoked; the
    // owner's records stay.
    let owners = SignedCheckpointRecord::sign(statement(&sealed, 5), &owner).unwrap();
    graph.checkpoints = vec![record.clone(), owners.clone()];
    assert_eq!(
        graph.checkpoints_at(sealed.id().unwrap()).unwrap(),
        vec![&record, &owners]
    );
    assert!(graph.checkpoints_at([0; 32]).unwrap().is_empty());
    assert!(
        graph
            .exclude_revoked(&revoking(&owner, &[issuer.public_key()]))
            .unwrap()
    );
    assert_eq!(
        graph.checkpoints_at(sealed.id().unwrap()).unwrap(),
        vec![&owners]
    );
}

#[test]
fn only_the_owner_signs_a_recovery_and_its_winning_seal_abandons_the_listed_entries() {
    let owner = PrivateKey::new();
    let trusted = PrivateKey::new();
    let mut graph = graph();
    let point = |position, byte| LogPoint {
        position,
        running: [byte; 32],
    };
    let recovered = |recovery| SealStatement {
        recovery: Some(recovery),
        ..seal(&graph, graph.genesis(), 3, &owner).statement
    };
    let recovery = Recovery {
        retained: point(2, 1),
        replaced: point(5, 2),
    };
    let signed = SignedSeal::sign(recovered(recovery), &owner).unwrap();
    signed.verify(owner.public_key(), &graph).unwrap();
    assert_eq!(
        signed.verify_recovery(owner.public_key()).unwrap(),
        &recovery
    );
    assert!(signed.verify_recovery(trusted.public_key()).is_err());
    assert!(
        seal(&graph, graph.genesis(), 3, &owner)
            .verify_recovery(owner.public_key())
            .is_err()
    );
    // A trusted identity's or an issuer's recovery is refused.
    for chain in [
        trusted_chain(&graph, &owner, &trusted),
        issuer_chain(&owner, &trusted),
    ] {
        let other = SignedSeal::endorse(recovered(recovery), &trusted, &chain).unwrap();
        assert!(other.verify(owner.public_key(), &graph).is_err());
        assert!(other.verify_recovery(owner.public_key()).is_err());
    }
    // A recovery keeps a prefix of the commit it ends and continues.
    for invalid in [
        Recovery {
            retained: point(6, 1),
            replaced: point(5, 2),
        },
        Recovery {
            retained: point(5, 1),
            replaced: point(5, 2),
        },
    ] {
        assert!(SignedSeal::sign(recovered(invalid), &owner).is_err());
    }
    let closing = SealStatement {
        action: SealAction::Close,
        ..recovered(recovery)
    };
    assert!(SignedSeal::sign(closing, &owner).is_err());

    graph.seals.push(signed);
    for (position, abandoned) in [(2, false), (3, true), (5, true), (6, false)] {
        assert_eq!(
            graph.abandons(graph.genesis(), position).unwrap(),
            abandoned
        );
    }
}

#[test]
fn bookmarks_on_a_recovered_tip_follow_the_recovery_and_explicit_moves_come_first() {
    let owner = PrivateKey::new();
    let mut graph = graph();
    let genesis = graph.genesis();
    for name in ["main", "release", "dev"] {
        graph
            .moves
            .push(movement(&graph, name, None, Some(genesis), &owner));
    }
    // `dev` moved to a branch first.
    let base = seal(&graph, genesis, 1, &owner);
    graph.seals.push(base.clone());
    let opened = opening(&graph, &base, &owner);
    graph.openings.push(opened.clone());
    let continued = base.successor().unwrap().unwrap();
    graph.moves.push(movement(
        &graph,
        "dev",
        Some(genesis),
        Some(opened.tip().unwrap()),
        &owner,
    ));
    // An ordinary seal does not move a bookmark by itself.
    assert_eq!(graph.bookmark("main").unwrap(), Some(genesis));
    graph.moves.push(movement(
        &graph,
        "main",
        Some(genesis),
        Some(continued),
        &owner,
    ));
    graph.moves.push(movement(
        &graph,
        "release",
        Some(genesis),
        Some(continued),
        &owner,
    ));
    let point = |position| LogPoint {
        position,
        running: [position as u8; 32],
    };
    let recovered = SignedSeal::sign(
        SealStatement {
            recovery: Some(Recovery {
                retained: point(1),
                replaced: point(2),
            }),
            ..seal(&graph, continued, 2, &owner).statement
        },
        &owner,
    )
    .unwrap();
    graph.seals.push(recovered.clone());
    let resumed = recovered.successor().unwrap();
    assert_eq!(graph.bookmark("main").unwrap(), resumed);
    assert_eq!(graph.bookmark("release").unwrap(), resumed);
    assert_eq!(graph.bookmark("dev").unwrap(), Some(opened.tip().unwrap()));
    // An explicit move off the recovered tip still resolves first.
    graph
        .moves
        .push(movement(&graph, "release", Some(continued), None, &owner));
    assert_eq!(graph.bookmark("release").unwrap(), None);
    assert_eq!(graph.bookmark("main").unwrap(), resumed);
}

#[test]
fn recovery_finality_binds_the_exact_replaced_head_and_keeps_the_signed_quorum() {
    use rocky_credentials::{
        GENESIS_LINE_FORMAT, GenesisLineStatement, SealFinality, SignedGenesisLine, TerminalAck,
    };
    let owner = PrivateKey::new();
    let mut graph = graph();
    let tip = graph.genesis();
    let recovery = Recovery {
        retained: LogPoint {
            position: 1,
            running: [1; 32],
        },
        replaced: LogPoint {
            position: 3,
            running: [3; 32],
        },
    };
    let ordinary = seal(&graph, tip, 1, &owner);
    let seal = SignedSeal::sign(
        SealStatement {
            recovery: Some(recovery),
            ..ordinary.statement
        },
        &owner,
    )
    .unwrap();
    let id = seal.id().unwrap();
    graph.seals.push(seal.clone());
    graph.genesis_lines.push(
        SignedGenesisLine::sign(
            GenesisLineStatement {
                format: GENESIS_LINE_FORMAT,
                scope: graph.scope,
                minimum_in_sync: 2,
            },
            &owner,
        )
        .unwrap(),
    );
    let nodes = [trusted_node(&graph, &owner), trusted_node(&graph, &owner)];
    let signed = |(position, running)| {
        nodes
            .iter()
            .map(|node| {
                let mut statement = ack(&graph, &seal, node).statement;
                statement.position = position;
                statement.running = running;
                TerminalAck::sign(statement, &node.0, node.1.clone()).unwrap()
            })
            .collect::<Vec<_>>()
    };
    for point in [(5, [9; 32]), (4, [9; 32])] {
        let proof = SealFinality::new(graph.scope, id, signed(point));
        assert!(
            graph
                .verify_finality(&proof, owner.public_key(), None)
                .is_err()
        );
    }
    let running = rocky_core::coordinated_chain(recovery.replaced.running, 4, id);
    let mut proof = SealFinality::new(graph.scope, id, signed((4, running)));
    graph
        .verify_finality(&proof, owner.public_key(), None)
        .unwrap();
    proof.acknowledgments.pop();
    assert!(
        graph
            .verify_finality(&proof, owner.public_key(), None)
            .is_err()
    );
}

#[test]
fn a_seal_in_the_parent_format_without_recovery_is_refused() {
    #[derive(serde::Serialize)]
    struct ParentStatement {
        format: u32,
        scope: Scope,
        tip: TipId,
        frontier: Vec<AuthorMark>,
        action: SealAction,
    }
    #[derive(serde::Serialize)]
    struct ParentSeal {
        statement: ParentStatement,
        endorsement: rocky_credentials::Endorsement,
    }
    let owner = PrivateKey::new();
    let graph = graph();
    let statement = ParentStatement {
        format: 1,
        scope: graph.scope,
        tip: graph.genesis(),
        frontier: vec![],
        action: SealAction::Continue {
            schema: graph.genesis_schema,
        },
    };
    let endorsement = rocky_credentials::Endorsement::sign(
        &owner,
        &CredentialChain::default(),
        "rocky.seal.v1",
        &statement,
    )
    .unwrap();
    let bytes = encode(&ParentSeal {
        statement,
        endorsement,
    })
    .unwrap();
    assert!(SignedSeal::from_bytes(&bytes).is_err());
}

#[test]
fn a_control_only_trusted_identity_certifies_acknowledgers_without_row_authority() {
    let graph = graph();
    let owner = PrivateKey::new();
    let identity = PrivateKey::new();
    let node = PrivateKey::new();
    let grant = Authority::owner(&owner)
        .issue_trusted(
            identity.public_key(),
            graph.scope,
            vec![],
            AuthorRange::ALL,
            (100, 1000, 0),
        )
        .unwrap();
    let chain = CredentialChain(vec![grant])
        .certify(&identity, node.public_key(), 1)
        .unwrap();
    assert_eq!(
        chain
            .trusted_node(owner.public_key(), graph.scope, node.public_key(), None)
            .unwrap(),
        identity.public_key()
    );
    let (grants, partitions) = chain
        .verify_selectors(
            owner.public_key(),
            node.public_key(),
            &RevocationSet::new(),
            200,
        )
        .unwrap();
    assert!(grants.is_empty());
    assert!(partitions.is_empty());
}
