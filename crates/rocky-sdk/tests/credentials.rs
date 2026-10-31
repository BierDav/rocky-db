//! Grant profiles, issuer devices, revocation with key rotation and
//! credentials supplied from outside the SDK. See
//! `docs/runtime/credentials.md` and `docs/runtime/sdk-enrollment.md`.
use common::{Device, Failure};
use rocky_sdk::{
    Database, Network, Open, Supplied,
    credentials::{
        Authority, CredentialChain, Credentials, PrivateKey, Revocation, SignedManifest,
    },
    transport::memory::Hub,
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

mod common;

const SCHEMA: &str = r#"{"application":"shopping","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"completed","type":"integer","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]},{"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"text","type":"text","not_null":true}],"primary_key":["key"]}]}"#;

fn memory(hub: &Arc<Hub>, name: &str) -> Network {
    Network::Owned(hub.connector(name))
}
fn open<'a>(directory: &'a Path, hub: &Arc<Hub>, name: &str) -> Open<'a> {
    Open {
        identity: None,
        directory,
        schema: SCHEMA,
        secrets: None,
        network: Some(memory(hub, name)),
        coordination: None,
    }
}
fn create(root: &Path, hub: &Arc<Hub>, name: &str) -> Result<Device, Failure> {
    Device::new(Database::create(open(&root.join(name), hub, name), None)?)
}
fn join(root: &Path, hub: &Arc<Hub>, name: &str, invitation: &str) -> Result<Device, Failure> {
    Device::new(Database::join(
        open(&root.join(name), hub, name),
        invitation,
    )?)
}
fn reopen(root: &Path, hub: &Arc<Hub>, name: &str) -> Result<Device, Failure> {
    Device::new(Database::open(open(&root.join(name), hub, name))?)
}
fn identity(root: &Path, name: &str) -> Result<Value, Failure> {
    let mut identity: Value =
        serde_json::from_slice(&std::fs::read(root.join(name).join("identity.json"))?)?;
    for epochs in identity["keys"].as_object_mut().ok_or("keys")?.values_mut() {
        for epoch in epochs.as_array_mut().ok_or("epochs")? {
            *epoch = epoch["generation"].clone();
        }
    }
    Ok(identity)
}
/// The secret of `role` in a device's file key store.
fn secret(root: &Path, name: &str, role: &str) -> Result<Option<[u8; 32]>, Failure> {
    let state: Value =
        serde_json::from_slice(&std::fs::read(root.join(name).join("identity.json"))?)?;
    let role = if let Some(reader) = role.strip_prefix("reader.") {
        let (collection, generation) = reader
            .split_once('.')
            .map_or((reader, 1u64), |(name, value)| {
                (name, value.parse().unwrap())
            });
        let epoch = state["keys"][collection].as_array().and_then(|epochs| {
            epochs
                .iter()
                .find(|epoch| epoch["generation"] == generation)
        });
        match epoch {
            Some(epoch) => {
                let epoch: rocky_core::KeyEpoch = serde_json::from_value(epoch.clone())?;
                format!(
                    "reader.{collection}.{}.{}",
                    epoch.generation,
                    data_encoding::HEXLOWER.encode(&epoch.secret_hash)
                )
            }
            None => return Ok(None),
        }
    } else {
        role.to_owned()
    };
    let installation = state["installation"]
        .as_str()
        .ok_or("installation")?
        .to_owned();
    let path = root
        .join(name)
        .join("secrets")
        .join(format!("rocky.{installation}.{role}"));
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes.try_into().map_err(|_| "secret length")?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn secrets(root: &Path, name: &str) -> Result<Vec<String>, Failure> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root.join(name).join("secrets"))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}
async fn create_row(
    device: &Device,
    handle: u8,
    collection: &str,
    values: Value,
) -> Result<Value, Failure> {
    device
        .call(json!({
            "type": "mutate",
            "handle": vec![handle; 32],
            "payload": json!({"type": "create", "collection": collection, "values": values}).to_string().into_bytes(),
            "entity": null,
            "baseline": null,
        }))
        .await
        .map_err(|error| error.to_string().into())
}
async fn note(device: &Device, handle: u8, text: &str) -> Result<Value, Failure> {
    create_row(device, handle, "notes", json!({"text": text})).await
}
async fn item(device: &Device, handle: u8, title: &str) -> Result<Value, Failure> {
    create_row(
        device,
        handle,
        "items",
        json!({"title": title, "completed": false}),
    )
    .await
}
/// The first column of every row `sql` selects, as text.
async fn texts(device: &Device, sql: &str) -> Result<Vec<String>, Failure> {
    let page = device
        .call(json!({"type": "read", "query": {"sql": sql, "values": [], "max_rows": 64}}))
        .await
        .map_err(|error| error.to_string())?;
    Ok(page["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row[0]["value"].as_str().map(String::from))
        .collect())
}
async fn notes(device: &Device) -> Result<Vec<String>, Failure> {
    texts(device, "SELECT text FROM notes ORDER BY text").await
}
async fn items(device: &Device) -> Result<Vec<String>, Failure> {
    texts(device, "SELECT title FROM items ORDER BY title").await
}
async fn session(device: &Device) -> Value {
    device.ok(json!({"type": "session"})).await
}
async fn synced(device: &Device) -> Result<(), Failure> {
    device
        .sync()
        .await
        .map(drop)
        .map_err(|e| e.to_string().into())
}

#[tokio::test]
async fn profiles_bound_reads_and_writes_across_renewal() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    let reader = json!({"kind": "reader", "scopes": ["items"]});
    let writer = json!({"kind": "writer", "scopes": ["notes"]});
    let r = join(root, &hub, "r", &a.invite_as(reader.clone()).await)?;
    let w = join(root, &hub, "w", &a.invite_as(writer.clone()).await)?;
    // A profile that names nothing, or an unknown collection, invites nobody.
    for profile in [
        json!({"kind": "reader", "scopes": []}),
        json!({"kind": "writer", "scopes": ["unknown"]}),
        json!({"kind": "writer", "scopes": ["items"], "rights": ["execute"]}),
        json!({"kind": "admin"}),
        Value::Null,
    ] {
        let refused = a.call(json!({"type": "pairing", "profile": profile})).await;
        assert!(refused.is_err(), "{profile}");
    }
    item(&a, 1, "Milk").await?;
    note(&a, 2, "Hello").await?;
    synced(&r).await?;
    synced(&w).await?;

    let check = async |renewed: bool| -> Result<(), Failure> {
        assert_eq!(session(&r).await["profile"], reader, "renewed {renewed}");
        assert_eq!(session(&w).await["profile"], writer, "renewed {renewed}");
        assert_eq!(identity(root, "r")?["profile"], reader);
        assert_eq!(identity(root, "r")?["keys"], json!({"items": [1]}));
        assert_eq!(identity(root, "w")?["keys"], json!({"notes": [1]}));
        // The reader reads its collection and writes nothing.
        assert_eq!(items(&r).await?, ["Milk"]);
        assert!(item(&r, 10, "Forged").await.is_err());
        assert!(note(&r, 11, "Forged").await.is_err());
        assert!(
            r.call(json!({"type": "pairing", "profile": reader}))
                .await
                .is_err()
        );
        assert!(notes(&r).await.unwrap_or_default().is_empty());
        // The scoped writer neither reads nor writes the other collection.
        assert_eq!(notes(&w).await?, ["Hello"]);
        assert!(item(&w, 12, "Forged").await.is_err());
        assert!(items(&w).await.unwrap_or_default().is_empty());
        assert!(w.call(json!({"type": "devices"})).await.is_err());
        Ok(())
    };
    check(false).await?;
    for device in [&r, &w] {
        let before = session(device).await;
        let renewed = device.ok(json!({"type": "renew"})).await;
        assert_eq!(renewed["readable"], before["readable"]);
        assert_eq!(renewed["writable"], before["writable"]);
        assert_eq!(renewed["principal"], before["principal"]);
    }
    check(true).await?;
    note(&w, 3, "From writer").await?;
    synced(&w).await?;
    assert_eq!(notes(&a).await?, ["From writer", "Hello"]);
    assert_eq!(items(&a).await?, ["Milk"]);
    // The issuer lists each device with the profile it enrolled as.
    let devices = a.ok(json!({"type": "devices"})).await;
    let mut profiles: Vec<Value> = devices["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|device| device["profile"].clone())
        .collect();
    profiles.sort_by_key(Value::to_string);
    assert_eq!(profiles, [reader, writer]);
    for device in [&a, &r, &w] {
        device.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn an_issuer_device_enrolls_and_renews_while_the_creator_is_closed() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    let i = join(
        root,
        &hub,
        "i",
        &a.invite_as(json!({"kind": "issuer"})).await,
    )?;
    item(&a, 1, "Milk").await?;
    synced(&i).await?;
    let (creator, issuer) = (session(&a).await, session(&i).await);
    assert_eq!(issuer["issuer"], json!(true));
    assert_eq!(issuer["profile"], json!({"kind": "issuer"}));
    // The issuer signs with its own identity through its chain: the
    // publisher key stays with the owner's identity and no copy exists.
    assert_ne!(issuer["node"], creator["node"]);
    assert_ne!(issuer["principal"], creator["principal"]);
    let (owner, paired) = (identity(root, "a")?, identity(root, "i")?);
    assert_eq!(paired["publisher"], owner["publisher"]);
    assert_eq!(owner["identity"], owner["publisher"]);
    assert_ne!(paired["identity"], paired["publisher"]);
    assert_ne!(
        secret(root, "i", "identity")?,
        secret(root, "a", "identity")?
    );
    for name in ["publisher", "user"] {
        assert_eq!(secret(root, "i", name)?, None);
    }
    // Revoking another issuer is the recovery path of `tests/issuers.rs`.
    let scope = a.database.scope();
    a.close().await;

    let m = join(root, &hub, "m", &i.invite().await)?;
    assert_eq!(m.database.scope(), scope);
    synced(&m).await?;
    assert_eq!(m.titles().await, ["Milk"]);
    m.add(2, "Eggs").await;
    synced(&m).await?;
    m.ok(json!({"type": "renew"})).await;
    assert_eq!(i.titles().await, ["Eggs", "Milk"]);
    let devices = i.ok(json!({"type": "devices"})).await.to_string();
    assert!(devices.contains(m.node().await.as_str()));
    for device in [&i, &m] {
        device.close().await;
    }
    let a = reopen(root, &hub, "a")?;
    let reopened = session(&a).await;
    assert_eq!(
        (&reopened["node"], &reopened["principal"]),
        (&creator["node"], &creator["principal"])
    );
    assert_eq!(a.database.scope(), scope);
    a.close().await;
    Ok(())
}

#[tokio::test]
async fn revocation_rotates_the_keys_remaining_readers_receive() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    let b = join(root, &hub, "b", &a.invite().await)?;
    let c = join(
        root,
        &hub,
        "c",
        &a.invite_as(json!({"kind": "reader", "scopes": ["items"]}))
            .await,
    )?;
    let w = join(
        root,
        &hub,
        "w",
        &a.invite_as(json!({"kind": "writer", "scopes": ["notes"]}))
            .await,
    )?;
    item(&a, 1, "Before").await?;
    for device in [&b, &c] {
        synced(device).await?;
        assert_eq!(items(device).await?, ["Before"]);
    }
    let revoked = a
        .ok(json!({"type": "revoke", "node": c.node().await}))
        .await;
    assert_eq!(revoked["revocations"]["statements"], 1);
    // Only the collections the revoked reader could read get a new epoch.
    assert_eq!(
        identity(root, "a")?["keys"],
        json!({"issuer_registry": [1], "items": [1, 2], "notes": [1]})
    );
    assert!(identity(root, "a")?["authority"]["rotation"].is_null());
    item(&a, 2, "After").await?;

    synced(&b).await?;
    assert_eq!(session(&b).await["revocations"]["statements"], 1);
    assert_eq!(identity(root, "b")?["keys"], json!({"items": [1, 2]}));
    assert_eq!(
        secret(root, "b", "reader.items.2")?,
        secret(root, "a", "reader.items.2")?
    );
    assert_eq!(items(&b).await?, ["After", "Before"]);
    item(&b, 3, "Rotated").await?;
    synced(&b).await?;
    assert_eq!(items(&a).await?, ["After", "Before", "Rotated"]);
    // A writer of another collection learns the policy, not the new key.
    synced(&w).await?;
    assert_eq!(session(&w).await["revocations"]["statements"], 1);
    assert_eq!(identity(root, "w")?["keys"], json!({"notes": [1]}));

    // The revoked reader gets neither the new key nor new rows.
    assert!(common::exchange_failed(&c.sync().await));
    assert!(c.call(json!({"type": "renew"})).await.is_err());
    assert!(!c.ok(json!({"type": "status"})).await["authority"]["verified_revocation"].is_null());
    assert_eq!(secret(root, "c", "reader.items.2")?, None);
    assert!(secrets(root, "c")?.iter().all(|name| !name.ends_with(".2")));
    assert_eq!(identity(root, "c")?["keys"], json!({"items": [1]}));
    assert!(
        !items(&c)
            .await
            .unwrap_or_default()
            .contains(&"After".into())
    );
    for device in [&a, &b, &c, &w] {
        device.close().await;
    }

    let reopened = reopen(root, &hub, "c")?;
    assert!(
        !reopened.ok(json!({"type": "status"})).await["authority"]["verified_revocation"].is_null()
    );
    reopened.close().await;
    // A local file cannot forge a publisher's revocation notice.
    let notice = root.join("c/revoked.json");
    let original = std::fs::read(&notice)?;
    let mut tampered: Value = serde_json::from_slice(&original)?;
    assert_eq!(tampered["version"], 2);
    tampered["statement"]["statement"]["time"] = json!(999);
    std::fs::write(&notice, serde_json::to_vec(&tampered)?)?;
    let reopened = reopen(root, &hub, "c")?;
    assert!(reopened.call(json!({"type": "status"})).await.is_err());
    reopened.close().await;
    std::fs::write(&notice, original)?;

    // A lost key epoch is an error at open, and is not made again.
    let before = secrets(root, "b")?;
    let role = before
        .iter()
        .find(|name| name.contains(".reader.items.2."))
        .ok_or("epoch 2 key")?;
    std::fs::remove_file(root.join("b/secrets").join(role))?;
    assert!(reopen(root, &hub, "b").is_err());
    assert_eq!(secrets(root, "b")?.len(), before.len() - 1);
    Ok(())
}

#[tokio::test]
async fn an_interrupted_revocation_completes_once_at_the_next_open() -> Result<(), Failure> {
    let root = common::identity::small_directory()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    let b = join(root, &hub, "b", &a.invite().await)?;
    let c = join(root, &hub, "c", &a.invite().await)?;
    item(&a, 1, "Before").await?;
    synced(&b).await?;
    let c_node = c.node().await;
    let devices = a.ok(json!({"type": "devices"})).await;
    let record = devices["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|device| device["node"] == c_node)
        .cloned()
        .ok_or("c's record")?;
    for device in [&a, &b, &c] {
        device.close().await;
    }
    // The intent and the record it acts on were saved and the new key
    // made; then the device stopped.
    let path = root.join("a/identity.json");
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let manifest = SignedManifest::from_bytes(
        &data_encoding::HEXLOWER.decode(saved["genesis"].as_str().ok_or("genesis")?.as_bytes())?,
    )?;
    let statement = Revocation {
        app: manifest
            .verify(serde_json::from_value(saved["publisher"].clone())?)?
            .app,
        issuer: serde_json::from_value(saved["identity"].clone())?,
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        nodes: [rocky_credentials::PeerId::of(serde_json::from_value(
            json!(c_node),
        )?)]
        .into(),
        identities: [serde_json::from_value(record["user"].clone())?].into(),
        capabilities: [rocky_core::Commitment::try_from(
            data_encoding::HEXLOWER
                .decode(
                    record["capability"]
                        .as_str()
                        .ok_or("capability")?
                        .as_bytes(),
                )?
                .as_slice(),
        )?]
        .into(),
    };
    let statement_id = statement.id()?;
    saved["authority"]["rotation"] = json!({
        "nodes": [c_node],
        "statement": statement,
        "keys": {"items": 2},
        "groups": {},
        "statements": [statement_id],
    });
    std::fs::write(&path, saved.to_string())?;
    let installation = saved["installation"].as_str().ok_or("installation")?;
    let made = [7; 32];
    std::fs::write(
        root.join("a/secrets")
            .join(format!("rocky.{installation}.rotation.reader.items.2")),
        made,
    )?;

    for round in 0..2 {
        let a = reopen(root, &hub, "a")?;
        assert_eq!(
            session(&a).await["revocations"]["statements"],
            1,
            "round {round}"
        );
        let saved = identity(root, "a")?;
        assert!(saved["authority"]["rotation"].is_null());
        assert_eq!(
            saved["keys"],
            json!({"issuer_registry": [1], "items": [1, 2], "notes": [1]})
        );
        let listed = a.ok(json!({"type": "devices"})).await;
        assert!(
            listed["devices"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|device| device["node"] == c_node && device["revoked"] == true),
            "{listed}"
        );
        // The statement signed at completion is the one the intent named.
        assert_eq!(saved["revocations"][0]["statement"], json!(statement));
        assert_eq!(secret(root, "a", "reader.items.2")?, Some(made));
        if round == 0 {
            item(&a, 2, "After").await?;
        }
        a.close().await;
    }
    let a = reopen(root, &hub, "a")?;
    let b = reopen(root, &hub, "b")?;
    synced(&b).await?;
    assert_eq!(session(&b).await["revocations"]["statements"], 1);
    assert_eq!(secret(root, "b", "reader.items.2")?, Some(made));
    assert_eq!(items(&b).await?, ["After", "Before"]);
    let c = reopen(root, &hub, "c")?;
    assert!(common::exchange_failed(&c.sync().await));
    assert_eq!(secret(root, "c", "reader.items.2")?, None);
    for device in [&a, &b, &c] {
        device.close().await;
    }
    Ok(())
}

/// Credentials an issuer outside the SDK made for `user`, from the
/// creator's identity and publisher key.
fn issued(
    root: &Path,
    user: rocky_sdk::credentials::PublicKey,
    grants_of: &str,
) -> Result<Credentials, Failure> {
    let creator = identity(root, "a")?;
    let owner = PrivateKey::from_bytes(&secret(root, "a", "identity")?.ok_or("identity")?);
    let revocations: rocky_sdk::credentials::RevocationSet =
        serde_json::from_value(creator["revocations"].clone())?;
    // The grants of an enrolled device's profile, without its keys.
    let model: CredentialChain =
        serde_json::from_value(identity(root, grants_of)?["credentials"].clone())?;
    let grants = model.0.first().ok_or("chain")?.capability.grants.clone();
    let authority = Authority::owner(&owner);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let capability = authority.issue(
        user,
        grants,
        rocky_credentials::AuthorRange::new(4096, 5119)?,
        (now, 3600, 300),
    )?;
    Ok(Credentials {
        publisher: owner.public_key(),
        revocations,
        chain: CredentialChain(vec![capability]),
    })
}

#[tokio::test]
async fn supplied_credentials_install_without_an_enrollment() -> Result<(), Failure> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let hub = Arc::new(Hub::default());
    let a = create(root, &hub, "a")?;
    // A writer of `items` whose grants the outside issuer copies.
    let model = join(root, &hub, "model", &a.invite().await)?;
    model.close().await;
    item(&a, 1, "Milk").await?;
    note(&a, 2, "Private").await?;

    let directory = root.join("s");
    let keys = Database::device(&directory, None)?;
    assert_eq!(Database::device(&directory, None)?, keys);
    let creator = identity(root, "a")?;
    let ids = || -> Result<_, Failure> {
        Ok((
            serde_json::from_value(creator["mesh"].clone())?,
            serde_json::from_value(creator["domain"].clone())?,
        ))
    };
    let items_key = secret(root, "a", "reader.items")?.ok_or("items key")?;
    let notes_key = secret(root, "a", "reader.notes")?.ok_or("notes key")?;
    let contact = a.contact().await;
    let supplied = |user, keys: Vec<(String, u64, [u8; 32])>| -> Result<Supplied, Failure> {
        let (mesh, domain) = ids()?;
        Ok(Supplied {
            mesh,
            domain,
            manifest: SignedManifest::from_bytes(
                &data_encoding::HEXLOWER
                    .decode(creator["genesis"].as_str().ok_or("genesis")?.as_bytes())?,
            )?,
            credentials: issued(root, user, "model")?,
            keys: keys
                .into_iter()
                .map(|(name, generation, key)| {
                    (name, rocky_core::KeyEpoch::new(generation, &key), key)
                })
                .collect(),
            epoch_statements: std::collections::BTreeMap::new(),
            issuers: vec![contact.clone()],
        })
    };
    let items_only = vec![("items".to_owned(), 1, items_key)];
    // A chain for another device, a key the grants do not read and a
    // missing reader key are all refused before anything is installed.
    let stranger = PrivateKey::new().public_key();
    for refused in [
        supplied(stranger, items_only.clone())?,
        supplied(
            keys.user,
            vec![items_only[0].clone(), ("notes".into(), 1, notes_key)],
        )?,
        supplied(keys.user, Vec::new())?,
    ] {
        assert!(Database::install(open(&directory, &hub, "s"), refused).is_err());
        assert!(!directory.join("identity.json").exists());
    }
    let s = Device::new(Database::install(
        open(&directory, &hub, "s"),
        supplied(keys.user, items_only)?,
    )?)?;
    assert_eq!(s.database.scope(), a.database.scope());
    let status = session(&s).await;
    assert_eq!(status["node"], json!(keys.node.to_hex()));
    assert_eq!(status["issuer"], json!(false));
    assert_eq!(
        status["profile"],
        json!({"kind": "writer", "scopes": ["items"]})
    );
    assert_eq!(secret(root, "s", "reader.notes")?, None);

    // The issuer serves only devices it knows or was told about.
    a.add_peer(&s.contact().await)
        .await
        .map_err(|e| e.to_string())?;
    s.add(3, "Eggs").await;
    synced(&s).await?;
    assert_eq!(items(&s).await?, ["Eggs", "Milk"]);
    assert_eq!(items(&a).await?, ["Eggs", "Milk"]);
    assert!(notes(&s).await.unwrap_or_default().is_empty());
    // Any issuer renews it with the grants it was supplied.
    s.ok(json!({"type": "renew"})).await;
    assert_eq!(
        session(&s).await["profile"],
        json!({"kind": "writer", "scopes": ["items"]})
    );
    // Installed once: the directory now holds a domain.
    assert!(Database::device(&directory, None).is_err());
    for device in [&a, &s] {
        device.close().await;
    }
    Ok(())
}

#[test]
fn a_grant_profile_names_exactly_its_kind_and_scopes() {
    use rocky_sdk::credentials::Profile;
    let parse = |value: Value| serde_json::from_value::<Profile>(value);
    assert_eq!(parse(json!({"kind": "issuer"})).ok(), Some(Profile::Issuer));
    assert!(parse(json!({"kind": "reader", "scopes": ["items"]})).is_ok());
    for refused in [
        json!({"kind": "issuer", "scopes": ["items"]}),
        json!({"kind": "reader", "scopes": ["items"], "rights": ["execute"]}),
        json!({"kind": "writer"}),
        json!({"kind": "owner"}),
        json!({"scopes": ["items"]}),
    ] {
        assert!(parse(refused.clone()).is_err(), "{refused}");
    }
}
