//! Envelope delivery between an issuer, a keyless custody mailbox and
//! members: directly, through mailboxes, at their bounds, across crashes and
//! after a revocation. See `docs/decisions/0054-envelope-delivery.md`.
use crate::{
    Database, Open, SecretStore, Session,
    delivery::{Mailbox, fault},
    transport::memory::Hub,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
};

type Failure = crate::Failure;

const SCHEMA: &str = r#"{"application":"delivery","version":1,"format":6,"tables":[
 {"name":"notes","class":"replayed","columns":[{"name":"key","type":"text","not_null":true}],"primary_key":["key"]},
 {"name":"parts","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"},
 {"name":"labels","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"],"partition_group":"list"}]}"#;
const TABLES: [&str; 3] = ["notes", "parts", "labels"];
/// The list every test shares.
const LIST: &str = "Weekend";

/// Keys in memory, kept across reopens of one directory.
#[derive(Default)]
struct Keys(Mutex<HashMap<String, Vec<u8>>>);
impl SecretStore for Keys {
    fn load(&self, name: &str) -> Result<Option<Vec<u8>>, Failure> {
        Ok(self.0.lock().map_err(|_| "poisoned")?.get(name).cloned())
    }
    fn store(&self, name: &str, secret: &[u8]) -> Result<(), Failure> {
        self.0
            .lock()
            .map_err(|_| "poisoned")?
            .insert(name.into(), secret.to_vec());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), Failure> {
        self.0.lock().map_err(|_| "poisoned")?.remove(name);
        Ok(())
    }
}
static KEYS: LazyLock<Mutex<HashMap<PathBuf, Arc<Keys>>>> = LazyLock::new(Default::default);
fn keys(directory: &Path) -> Arc<dyn SecretStore> {
    KEYS.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(directory.to_path_buf())
        .or_default()
        .clone()
}

struct Device {
    database: Arc<Database>,
    session: Session,
    scope: Value,
    directory: PathBuf,
    name: String,
    hub: Arc<Hub>,
}
fn open<'a>(directory: &'a Path, hub: &Arc<Hub>, name: &str) -> Open<'a> {
    Open {
        identity: None,
        directory,
        schema: SCHEMA,
        secrets: Some(keys(directory)),
        network: Some(crate::Network::Owned(hub.connector(name))),
        coordination: None,
    }
}
impl Device {
    fn new(database: Arc<Database>, directory: PathBuf, name: &str, hub: &Arc<Hub>) -> Self {
        Self {
            session: database.session(),
            scope: serde_json::from_str(&database.scope()).unwrap_or_default(),
            database,
            directory,
            name: name.into(),
            hub: hub.clone(),
        }
    }
    async fn reply(&self, request: Value) -> Result<Value, String> {
        let reply: Value = serde_json::from_str(
            &self
                .session
                .call(json!({"version":1,"scope":self.scope,"request":request}).to_string())
                .await
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        match reply["status"] == "ok" {
            true => Ok(reply["value"].clone()),
            false => Err(reply["error"].to_string()),
        }
    }
    async fn ok(&self, request: Value) -> Result<Value, Failure> {
        Ok(self
            .reply(request.clone())
            .await
            .map_err(|error| format!("{request}: {error}"))?)
    }
    async fn node(&self) -> Result<String, Failure> {
        Ok(self.ok(json!({"type":"session"})).await?["node"]
            .as_str()
            .ok_or("node")?
            .to_owned())
    }
    async fn online(&self, online: bool) -> Result<(), Failure> {
        self.ok(json!({"type":"networking_control","enabled":online}))
            .await
            .map(drop)
    }
    /// Closes the database and opens it again from its directory, as after
    /// a crash: nothing but what it saved survives.
    async fn restart(self) -> Result<Self, Failure> {
        let Self {
            database,
            session,
            directory,
            name,
            hub,
            ..
        } = self;
        drop(session);
        database.close().await?;
        let database = Database::open(open(&directory, &hub, &name))?.database;
        Ok(Self::new(database, directory, &name, &hub))
    }
    async fn invite(&self, profile: Value) -> Result<String, Failure> {
        Ok(
            self.ok(json!({"type":"pairing","profile":profile})).await?["uri"]
                .as_str()
                .ok_or("uri")?
                .to_owned(),
        )
    }
    async fn epochs(&self) -> Result<Vec<Value>, Failure> {
        Ok(self
            .ok(json!({"type":"partition_status","group":"list","values":values()}))
            .await?["epochs"]
            .as_array()
            .ok_or("epochs")?
            .iter()
            .map(|epoch| epoch["generation"].clone())
            .collect())
    }
    /// How this sharer sees `node`'s latest envelope.
    async fn state(&self, node: &str) -> Result<Value, Failure> {
        let status = self
            .ok(json!({"type":"partition_status","group":"list","values":values()}))
            .await?;
        Ok(status["recipients"]
            .as_array()
            .ok_or("recipients")?
            .iter()
            .filter(|recipient| recipient["node"] == node)
            .max_by_key(|recipient| recipient["epoch"]["generation"].as_u64())
            .map(|recipient| recipient["state"].clone())
            .unwrap_or_default())
    }
    async fn events(&self, kind: &str) -> Result<Vec<Value>, Failure> {
        Ok(self.ok(json!({"type":"activity"})).await?["events"]
            .as_array()
            .ok_or("events")?
            .iter()
            .filter(|event| event["kind"] == kind)
            .cloned()
            .collect())
    }
    fn mailbox(&self) -> Result<Mailbox, Failure> {
        Mailbox::open(&self.directory.join("mailbox.json"))
    }
    async fn close(self) -> Result<(), Failure> {
        drop(self.session);
        self.database.close().await
    }
}
fn values() -> Value {
    json!([{"type":"text","value":LIST}])
}
async fn introduce(left: &Device, right: &Device) -> Result<(), Failure> {
    for (from, to) in [(left, right), (right, left)] {
        let contact = to.ok(json!({"type":"contact"})).await?;
        from.ok(json!({"type":"peer_add","contact":contact["uri"]}))
            .await?;
    }
    Ok(())
}
/// An issuer, a keyless custody peer and a writer, which meet each other
/// only through custody unless a test introduces them.
struct Mesh {
    root: crate::test_directory::Directory,
    hub: Arc<Hub>,
    a: Device,
    custody: Device,
    b: Device,
}
impl Mesh {
    async fn new() -> Result<Self, Failure> {
        Self::with_root(tempfile::tempdir()?.into()).await
    }
    async fn with_root(root: crate::test_directory::Directory) -> Result<Self, Failure> {
        let hub = Arc::new(Hub::default());
        let directory = root.path().join("a");
        let a = Device::new(
            Database::create(open(&directory, &hub, "a"), None)?.database,
            directory,
            "a",
            &hub,
        );
        let custody = join(
            &root,
            &hub,
            &a,
            "custody",
            json!({"kind":"custody","scopes":TABLES}),
        )
        .await?;
        let b = join(
            &root,
            &hub,
            &a,
            "b",
            json!({"kind":"writer","scopes":TABLES}),
        )
        .await?;
        introduce(&a, &custody).await?;
        introduce(&b, &custody).await?;
        a.ok(json!({"type":"partition_create","group":"list","values":values()}))
            .await?;
        Ok(Self {
            root,
            hub,
            a,
            custody,
            b,
        })
    }
    /// A reader without a custody grant, which knows custody.
    async fn member(&self, name: &str) -> Result<Device, Failure> {
        let device = join(
            &self.root,
            &self.hub,
            &self.a,
            name,
            json!({"kind":"grants","grants": TABLES.map(|scope| json!({"scope":scope,"rights":["read"]}))}),
        )
        .await?;
        introduce(&device, &self.custody).await?;
        Ok(device)
    }
    async fn close(self) -> Result<(), Failure> {
        for device in [self.a, self.custody, self.b] {
            device.close().await?;
        }
        Ok(())
    }
}
async fn join(
    root: &tempfile::TempDir,
    hub: &Arc<Hub>,
    issuer: &Device,
    name: &str,
    profile: Value,
) -> Result<Device, Failure> {
    let directory = root.path().join(name);
    let invitation = issuer.invite(profile).await?;
    let device = Device::new(
        Database::join(open(&directory, hub, name), &invitation)?.database,
        directory,
        name,
        hub,
    );
    // The join's own first sync runs in the background: let it finish, so
    // that no pass still in flight meets a later share.
    let mut status = device.ok(json!({"type":"status"})).await?;
    while status["data"]["bootstrap_pending"] == true {
        status = device
            .ok(json!({"type":"status_next","after":status["token"]}))
            .await?;
    }
    Ok(device)
}
/// `from` syncs while `to` is offline; custody is always online.
async fn relay(from: &Device, to: &Device) -> Result<Value, String> {
    to.online(false).await.map_err(|error| error.to_string())?;
    from.online(true).await.map_err(|error| error.to_string())?;
    from.reply(json!({"type":"sync"})).await
}
fn share(recipients: &[&str]) -> Value {
    json!({"type":"partition_share","group":"list","values":values(),"recipients":recipients})
}
/// The sum of one count over every round of delivery.
async fn delivered(device: &Device, count: &str) -> Result<u64, Failure> {
    Ok(device
        .events("envelopes_delivered")
        .await?
        .iter()
        .filter_map(|event| event[count].as_u64())
        .sum())
}
/// Every file `directory` holds, concatenated.
fn stored(directory: &Path) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            bytes.extend(std::fs::read(entry.path())?);
        }
    }
    Ok(bytes)
}
fn contains(bytes: &[u8], pattern: &[u8]) -> bool {
    bytes.windows(pattern.len()).any(|window| window == pattern)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_share_and_a_rotation_reach_an_offline_recipient_through_custody_alone()
-> Result<(), Failure> {
    let mesh = Mesh::with_root(super::sync_tests::small_directory()?).await?;
    let third = mesh.member("third").await?;
    let removed = mesh.member("removed").await?;
    let Mesh { a, custody, b, .. } = &mesh;
    mesh.hub.record("third");
    let node = b.node().await?;
    b.online(false).await?;
    // Shared while B is offline; then a reader's revocation rotates the list.
    let removed_node = removed.node().await?;
    a.ok(share(&[&node, &third.node().await?, &removed_node]))
        .await?;
    a.ok(json!({"type":"revoke","node":removed_node})).await?;
    assert_eq!(a.state(&node).await?, "pending");
    relay(a, b).await?;
    assert_eq!(a.state(&node).await?, "deposited");
    assert_eq!(
        custody.mailbox()?.len(),
        4,
        "a share and a rotation each for B and the third member"
    );
    // The mailbox stores recipients' node keys and nothing naming the list.
    let held = std::fs::read(custody.directory.join("mailbox.json"))?;
    let address = a
        .ok(json!({"type":"partition_status","group":"list","values":values()}))
        .await?["address"]
        .as_str()
        .ok_or("address")?
        .to_owned();
    for named in [LIST, "\"list\"", "parts", address.as_str()] {
        assert!(
            !contains(&held, named.as_bytes()),
            "the mailbox names {named}"
        );
    }
    // B meets only custody: both envelopes arrive and install.
    relay(b, a).await?;
    assert_eq!(b.epochs().await?, [json!(1), json!(2)]);
    third.ok(json!({"type":"sync"})).await?;
    // The sender learns of the delivery from custody, which then forgets it.
    relay(a, b).await?;
    assert_eq!(a.state(&node).await?, "delivered");
    assert_eq!(custody.mailbox()?.len(), 0);
    assert_eq!(
        b.state(&node).await?,
        Value::Null,
        "status is the sharer's alone"
    );

    // A member without custody sees no recipient identity in its sessions
    // or replica; a mailbox sees the recipient but no partition.
    let key: rocky_secure::PublicKey = node.parse()?;
    let transcript = mesh.hub.transcript("third");
    assert!(!transcript.is_empty());
    let replica = stored(&third.directory)?;
    for (what, bytes) in [("transcript", &transcript), ("replica", &replica)] {
        for pattern in encodings(key.as_bytes()) {
            assert!(
                !contains(bytes, &pattern),
                "the third member's {what} names the recipient"
            );
        }
    }
    third.close().await?;
    removed.close().await?;
    mesh.close().await
}
/// How a node key may appear on the wire or on disk: raw, hexadecimal,
/// and inside one or two layers of CBOR byte arrays.
fn encodings(key: &[u8]) -> Vec<Vec<u8>> {
    let uints = |bytes: &[u8]| -> Vec<u8> {
        bytes
            .iter()
            .flat_map(|byte| match byte {
                0..24 => vec![*byte],
                _ => vec![24, *byte],
            })
            .collect()
    };
    let hex = data_encoding::HEXLOWER.encode(key).into_bytes();
    vec![
        key.to_vec(),
        uints(key),
        uints(&uints(key)),
        hex.clone(),
        uints(&hex),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_delivered_directly_and_through_two_mailboxes_installs_once()
-> Result<(), Failure> {
    let mesh = Mesh::with_root(super::sync_tests::small_directory()?).await?;
    let Mesh { a, custody, b, .. } = &mesh;
    let second = join(
        &mesh.root,
        &mesh.hub,
        a,
        "second",
        json!({"kind":"custody","scopes":TABLES}),
    )
    .await?;
    introduce(a, &second).await?;
    introduce(b, &second).await?;
    let node = b.node().await?;
    b.online(false).await?;
    a.ok(share(&[&node])).await?;
    relay(a, b).await?;
    assert_eq!(custody.mailbox()?.len(), 1);
    assert_eq!(second.mailbox()?.len(), 1);
    // B meets A and both mailboxes in one sync.
    introduce(a, b).await?;
    b.online(true).await?;
    b.ok(json!({"type":"sync"})).await?;
    assert_eq!(delivered(b, "received").await?, 3);
    assert_eq!(b.events("partition_key_installed").await?.len(), 1);
    assert_eq!(b.epochs().await?, [json!(1)]);
    assert_eq!(a.state(&node).await?, "delivered");
    // Both mailboxes keep only B's receipt until A takes it.
    a.ok(json!({"type":"sync"})).await?;
    assert_eq!(custody.mailbox()?.len() + second.mailbox()?.len(), 0);
    second.close().await?;
    mesh.close().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mailbox_serves_only_the_recipient_and_refuses_at_its_bound_while_the_sender_keeps_it()
-> Result<(), Failure> {
    let Mesh {
        root,
        hub,
        a,
        custody,
        b,
    } = Mesh::with_root(super::sync_tests::small_directory()?).await?;
    let mesh_member = |name: &'static str| {
        let (root, hub, a, custody) = (&root, &hub, &a, &custody);
        async move {
            let device = join(root, hub, a, name, json!({"kind":"grants","grants": TABLES.map(|scope| json!({"scope":scope,"rights":["read"]}))})).await?;
            introduce(&device, custody).await?;
            Ok::<_, Failure>(device)
        }
    };
    let other = mesh_member("other").await?;
    let removed = mesh_member("removed").await?;
    let node = b.node().await?;
    b.online(false).await?;
    a.ok(share(&[&node])).await?;
    relay(&a, &b).await?;
    // Another member collects nothing of B's.
    other.ok(json!({"type":"sync"})).await?;
    assert_eq!(delivered(&other, "received").await?, 0);
    assert_eq!(custody.mailbox()?.len(), 1);

    // Fill custody's room for B: the rotation's envelope is refused by name.
    let recipient: rocky_secure::PublicKey = node.parse()?;
    let custody = custody
        .restart_with(|mailbox| {
            let depositor = rocky_secure::PrivateKey::new().public_key();
            while mailbox.len() < crate::delivery::RECIPIENT_DEPOSITS {
                let filler = rocky_credentials::SealedDelivery::seal(recipient, b"filler")?;
                mailbox.deposit(depositor, &filler, crate::enrollment::now()?)?;
            }
            Ok(())
        })
        .await?;
    a.ok(json!({"type":"revoke","node":removed.node().await?}))
        .await?;
    relay(&a, &b).await?;
    assert_eq!(
        delivered(&a, "refused").await?,
        1,
        "no room for B's rotation"
    );
    let status = a
        .ok(json!({"type":"partition_status","group":"list","values":values()}))
        .await?;
    let rotated: Vec<&Value> = status["recipients"]
        .as_array()
        .ok_or("recipients")?
        .iter()
        .filter(|entry| entry["node"] == node && entry["epoch"]["generation"] == 2)
        .collect();
    assert_eq!(rotated.len(), 1);
    assert_eq!(rotated[0]["state"], "pending", "the sender keeps it");
    for device in [removed, other, a, custody, b] {
        device.close().await?;
    }
    Ok(())
}

#[test]
fn a_mailbox_refuses_at_both_bounds_and_forgets_what_expired() -> Result<(), Failure> {
    use crate::delivery::{DEPOSIT_LIFETIME, MAILBOX_DEPOSITS, MAILBOX_FULL, RECIPIENT_DEPOSITS};
    let root = tempfile::tempdir()?;
    let mut mailbox = Mailbox::open(&root.path().join("mailbox.json"))?;
    let depositor = rocky_secure::PrivateKey::new().public_key();
    let recipients: Vec<_> = (0..MAILBOX_DEPOSITS / RECIPIENT_DEPOSITS + 1)
        .map(|_| rocky_secure::PrivateKey::new().public_key())
        .collect();
    let deposit = |mailbox: &mut Mailbox, recipient, time| {
        let delivery = rocky_credentials::SealedDelivery::seal(recipient, b"envelope")?;
        mailbox.deposit(depositor, &delivery, time)
    };
    for _ in 0..RECIPIENT_DEPOSITS {
        assert_eq!(deposit(&mut mailbox, recipients[0], 0)?, None);
    }
    let full = deposit(&mut mailbox, recipients[0], 0)?.ok_or("stored past the bound")?;
    assert!(full.starts_with(MAILBOX_FULL), "{full}");
    for recipient in &recipients[1..MAILBOX_DEPOSITS / RECIPIENT_DEPOSITS] {
        for _ in 0..RECIPIENT_DEPOSITS {
            assert_eq!(deposit(&mut mailbox, *recipient, 1)?, None);
        }
    }
    assert_eq!(mailbox.len(), MAILBOX_DEPOSITS);
    let last = *recipients.last().ok_or("recipient")?;
    let full = deposit(&mut mailbox, last, 1)?.ok_or("stored past the bound")?;
    assert!(full.starts_with(MAILBOX_FULL), "{full}");
    // Saved and reopened, then 30 days after the first arrived.
    mailbox.save()?;
    let mut mailbox = Mailbox::open(&root.path().join("mailbox.json"))?;
    assert_eq!(mailbox.len(), MAILBOX_DEPOSITS);
    assert!(mailbox.sweep(DEPOSIT_LIFETIME, |_| false));
    assert_eq!(mailbox.len(), MAILBOX_DEPOSITS - RECIPIENT_DEPOSITS);
    assert!(mailbox.sweep(DEPOSIT_LIFETIME + 1, |_| false));
    assert_eq!(mailbox.len(), 0);
    assert_eq!(deposit(&mut mailbox, last, DEPOSIT_LIFETIME + 1)?, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_recipient_revoked_after_the_deposit_gets_nothing_and_the_deposit_is_removed()
-> Result<(), Failure> {
    let Mesh {
        root,
        hub,
        a,
        custody,
        b,
    } = Mesh::new().await?;
    let node = b.node().await?;
    b.online(false).await?;
    a.ok(share(&[&node])).await?;
    relay(&a, &b).await?;
    assert_eq!(custody.mailbox()?.len(), 1);
    // A restarted mailbox keeps the deposit.
    let custody = custody.restart_with(|_| Ok(())).await?;
    assert_eq!(custody.mailbox()?.len(), 1);
    a.ok(json!({"type":"revoke","node":node})).await?;
    assert_eq!(a.state(&node).await?, Value::Null, "the sender dropped it");
    // Custody learns the statement from A and removes B's deposit.
    a.ok(json!({"type":"sync"})).await?;
    assert_eq!(custody.mailbox()?.len(), 0);
    let _ = relay(&b, &a).await;
    assert_eq!(b.epochs().await?, Vec::<Value>::new(), "B received nothing");
    for device in [a, custody, b] {
        device.close().await?;
    }
    drop((root, hub));
    Ok(())
}

impl Device {
    /// Restarts the device after `change` edited its saved mailbox.
    async fn restart_with(
        self,
        change: impl FnOnce(&mut Mailbox) -> Result<(), Failure>,
    ) -> Result<Self, Failure> {
        let Self {
            database,
            session,
            directory,
            name,
            hub,
            ..
        } = self;
        drop(session);
        database.close().await?;
        let mut mailbox = Mailbox::open(&directory.join("mailbox.json"))?;
        change(&mut mailbox)?;
        mailbox.save()?;
        let database = Database::open(open(&directory, &hub, &name))?.database;
        Ok(Self::new(database, directory, &name, &hub))
    }
}

/// Where a sweep stops: on the sender, the mailbox or the recipient.
#[derive(Clone, Copy)]
enum At {
    Sender,
    Mailbox,
    Recipient,
}
/// Stops one device once at `stage`, restarts it from disk and goes on: B
/// still installs the envelope once, A learns it was delivered and custody
/// keeps nothing. `direct` runs A and B together; otherwise they meet
/// only custody.
async fn sweep(direct: bool, at: At, stage: fault::Stage) -> Result<(), Failure> {
    let Mesh {
        root,
        hub,
        a,
        custody,
        b,
    } = Mesh::new().await?;
    if direct {
        introduce(&a, &b).await?;
    }
    let node = b.node().await?;
    let stopped: rocky_secure::PublicKey = match at {
        At::Sender => a.node().await?.parse()?,
        At::Mailbox => custody.node().await?.parse()?,
        At::Recipient => node.parse()?,
    };
    b.online(direct).await?;
    a.ok(json!({"type":"partition_share","group":"list","values":values(),"recipients":[node]}))
        .await?;
    let pending = || -> Result<bool, Failure> {
        Ok(fault::STOPS
            .lock()
            .map_err(|_| "poisoned")?
            .contains(&(stopped, stage)))
    };
    fault::STOPS
        .lock()
        .map_err(|_| "poisoned")?
        .push((stopped, stage));
    let mut devices = [Some(a), Some(custody), Some(b)];
    let index = match at {
        At::Sender => 0,
        At::Mailbox => 1,
        At::Recipient => 2,
    };
    let mut restarted = false;
    for _ in 0..4 {
        // A, then B, syncs alone, unless both are online throughout.
        for (from, to) in [(0, 2), (2, 0)] {
            let (Some(sender), Some(receiver)) = (&devices[from], &devices[to]) else {
                return Err("a device is missing".into());
            };
            if !direct {
                receiver.online(false).await?;
            }
            sender.online(true).await?;
            let _ = sender.reply(json!({"type":"sync"})).await;
            if !restarted && !pending()? {
                restarted = true;
                let device = devices[index].take().ok_or("stopped device")?;
                if stage == fault::Stage::Deposited {
                    let saved: Value = serde_json::from_slice(&std::fs::read(
                        device.directory.join("identity.json"),
                    )?)?;
                    let pending = saved["deliveries"].as_object().ok_or("outbox")?;
                    assert!(
                        pending.values().any(|entry| entry["targets"]
                            .as_array()
                            .is_some_and(|targets| !targets.is_empty())
                            && entry["mailboxes"] == json!([])),
                        "a lost deposit answer keeps its durable mailbox reservation"
                    );
                }
                devices[index] = Some(device.restart().await?);
            }
        }
    }
    assert!(restarted, "{stage:?} was never reached");
    let [Some(a), Some(custody), Some(b)] = devices else {
        return Err("a device is missing".into());
    };
    assert_eq!(b.epochs().await?, [json!(1)], "{stage:?}");
    assert_eq!(a.state(&node).await?, "delivered", "{stage:?}");
    assert_eq!(custody.mailbox()?.len(), 0, "{stage:?}");
    for device in [a, custody, b] {
        device.close().await?;
    }
    drop((root, hub));
    Ok(())
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_recipient_after_a_direct_install_loses_no_envelope() -> Result<(), Failure>
{
    sweep(true, At::Recipient, fault::Stage::Installed).await
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_sender_before_saving_a_direct_receipt_loses_no_envelope()
-> Result<(), Failure> {
    sweep(true, At::Sender, fault::Stage::Receipts).await
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_mailbox_after_storing_a_deposit_loses_no_envelope() -> Result<(), Failure> {
    sweep(false, At::Mailbox, fault::Stage::Stored).await
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_sender_before_recording_a_deposit_loses_no_envelope() -> Result<(), Failure>
{
    sweep(false, At::Sender, fault::Stage::Deposited).await
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_recipient_after_installing_a_deposit_loses_no_envelope()
-> Result<(), Failure> {
    sweep(false, At::Recipient, fault::Stage::Installed).await
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_mailbox_before_keeping_the_receipt_loses_no_envelope() -> Result<(), Failure>
{
    sweep(false, At::Mailbox, fault::Stage::Replaced).await
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_sender_before_saving_a_relayed_receipt_loses_no_envelope()
-> Result<(), Failure> {
    sweep(false, At::Sender, fault::Stage::Receipts).await
}
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_mailbox_before_forgetting_a_taken_receipt_loses_no_envelope()
-> Result<(), Failure> {
    sweep(false, At::Mailbox, fault::Stage::Forgotten).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_deposits_its_share_with_custody_for_an_offline_recipient() -> Result<(), Failure>
{
    let mesh = Mesh::with_root(super::sync_tests::small_directory()?).await?;
    let member = mesh.member("sharer").await?;
    let recipient = mesh.b.node().await?;
    mesh.a.ok(share(&[&member.node().await?])).await?;
    introduce(&mesh.a, &member).await?;
    member.ok(json!({"type":"sync"})).await?;
    mesh.a.online(false).await?;
    mesh.b.online(false).await?;
    member.ok(share(&[&recipient])).await?;
    member.ok(json!({"type":"sync"})).await?;
    assert_eq!(member.state(&recipient).await?, "deposited");
    member.online(false).await?;
    mesh.b.online(true).await?;
    mesh.b.ok(json!({"type":"sync"})).await?;
    assert_eq!(mesh.b.epochs().await?, [json!(1)]);
    member.online(true).await?;
    member.ok(json!({"type":"sync"})).await?;
    assert_eq!(member.state(&recipient).await?, "delivered");
    member.close().await?;
    mesh.close().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crash_of_the_recipient_after_preparing_bootstrap_loses_no_envelope()
-> Result<(), Failure> {
    sweep(false, At::Recipient, fault::Stage::Prepared).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_custody_grant_on_an_unrelated_scope_is_enough_to_hold_deliveries() -> Result<(), Failure>
{
    let mesh = Mesh::new().await?;
    let mailbox = join(
        &mesh.root,
        &mesh.hub,
        &mesh.a,
        "raw-custody",
        json!({"kind":"grants","grants":[{"scope":"notes","rights":["custody"]}]}),
    )
    .await?;
    introduce(&mesh.a, &mailbox).await?;
    introduce(&mesh.b, &mailbox).await?;
    mesh.custody.online(false).await?;
    let recipient = mesh.b.node().await?;
    mesh.b.online(false).await?;
    mesh.a.ok(share(&[&recipient])).await?;
    // The delivery round succeeds independently of row sync: this mailbox
    // has no grant on the list, so the later row exchange may be refused.
    let _ = mesh.a.reply(json!({"type":"sync"})).await;
    assert_eq!(mesh.a.state(&recipient).await?, "deposited");
    assert_eq!(mailbox.mailbox()?.len(), 1);
    mesh.a.online(false).await?;
    mesh.b.online(true).await?;
    let _ = mesh.b.reply(json!({"type":"sync"})).await;
    assert_eq!(mesh.b.epochs().await?, [json!(1)]);
    mailbox.close().await?;
    mesh.close().await
}
