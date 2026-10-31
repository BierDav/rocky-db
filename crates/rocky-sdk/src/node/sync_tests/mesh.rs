use super::*;
use rocky_secure::network::{ContactHandler, ContactHint, ContactRequest, ContactResponse};

async fn contact(from: &Node, to: &Node) -> Result<PublicKey, Failure> {
    let link = to.network.read().await;
    let uri = to
        .settings
        .lock()
        .await
        .contact(&to.vault, &*link.as_ref().ok_or("link")?.transport)
        .await?
        .0;
    from.configure(|settings| settings.add_peer(&from.vault, &uri))
        .await
}
async fn pass(node: &Node) -> Result<Value, Failure> {
    let link = node.network.read().await;
    Ok(node.sync(&*link.as_ref().ok_or("link")?.transport).await?.0)
}
fn writer() -> Profile {
    Profile::Writer {
        scopes: ["items".into()].into(),
    }
}

#[tokio::test]
async fn one_contact_hands_over_a_second_and_answers_a_request_for_a_third() -> Result<(), Failure>
{
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let b = enrolled(&root.path().join("b"), &hub, "b", Some((&a, writer()))).await?;
            let c = enrolled(&root.path().join("c"), &hub, "c", Some((&a, writer()))).await?;
            let d = enrolled(&root.path().join("d"), &hub, "d", Some((&a, writer()))).await?;
            let c_key = contact(&a, &c).await?;
            let d_key = contact(&a, &d).await?;
            let a_link = a.network.read().await;
            let c_contact = a.settings.lock().await.peers[&c_key].clone();
            a.reconcile(
                &*a_link.as_ref().ok_or("link")?.transport,
                c_key,
                &c_contact,
            )
            .await?;
            drop(a_link);
            assert_eq!(b.settings.lock().await.peers.len(), 1);
            pass(&b).await?;
            assert_eq!(
                b.settings.lock().await.contact_meta[&c_key].source,
                "handover"
            );
            assert!(!b.settings.lock().await.peers.contains_key(&d_key));
            let b_link = b.network.read().await;
            assert_eq!(
                b.request_contact(
                    &*b_link.as_ref().ok_or("link")?.transport,
                    secure_node_id(d_key)
                )
                .await?["node"],
                d_key.to_hex()
            );
            drop(b_link);
            assert_eq!(
                b.settings.lock().await.contact_meta[&d_key].source,
                "request"
            );
            let a_key = PrivateKey::from_bytes(&a.vault.get("node")?).public_key();
            b.configure(|settings| settings.remove_peer(a_key)).await?;
            pass(&b).await?;
            assert!(hub.dials_to("c") > 1);
            assert!(
                b.reached()?
                    .get(&d_key)
                    .is_some_and(|last| last.error.is_none())
            );
            for node in [&a, &b, &c, &d] {
                node.detach(None).await;
            }
            Ok(())
        })
        .await
}
#[tokio::test]
async fn a_sufficient_local_peer_is_the_only_dial_and_reports_the_skipped_issuer()
-> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let b = enrolled(&root.path().join("b"), &hub, "b", Some((&a, writer()))).await?;
            let c = enrolled(&root.path().join("c"), &hub, "c", Some((&a, writer()))).await?;
            let key = contact(&b, &c).await?;
            b.configure(|settings| {
                settings.contact_meta.get_mut(&key).ok_or("meta")?.local = true;
                Ok(())
            })
            .await?;
            let dials = hub.dials_to("a");
            assert_eq!(completed_peers(&pass(&b).await?), 1);
            assert_eq!(hub.dials_to("a"), dials);
            let peers = b.peers().await;
            assert_eq!(
                peers
                    .iter()
                    .find(|peer| peer["node"] == key.to_hex())
                    .ok_or("local")?["choice"],
                "selected_local"
            );
            assert_eq!(
                peers
                    .iter()
                    .find(|peer| peer["issuer"] == true)
                    .ok_or("issuer")?["choice"],
                "covered"
            );
            assert!(!b.reached()?.get(&key).ok_or("reached")?.held.is_empty());
            assert!(
                b.vault
                    .load_bytes("discovery")?
                    .is_none_or(|bytes| !bytes.is_empty())
            );
            for node in [&a, &b, &c] {
                node.detach(None).await;
            }
            Ok(())
        })
        .await
}
#[tokio::test]
async fn an_unreachable_contact_costs_no_dial_during_its_backoff() -> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let key = PrivateKey::new().public_key();
            a.configure(|settings| {
                settings.learn_contact(
                    &a.vault,
                    ContactHint {
                        node: key,
                        routes: vec![("memory".into(), "gone".into())],
                        trusted: false,
                    },
                    "handover",
                    now()?,
                )
            })
            .await?;
            assert_eq!(completed_peers(&pass(&a).await?), 0);
            let dials = hub.dials_to("gone");
            assert_eq!(completed_peers(&pass(&a).await?), 0);
            assert_eq!(hub.dials_to("gone"), dials);
            assert_eq!(a.peers().await[0]["choice"], "backoff");
            a.detach(None).await;
            Ok(())
        })
        .await
}
#[tokio::test]
async fn revoked_peers_receive_no_contact_or_discovery_material_and_are_unknown_to_requests()
-> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let b = enrolled(&root.path().join("b"), &hub, "b", Some((&a, writer()))).await?;
            let c = enrolled(&root.path().join("c"), &hub, "c", Some((&a, writer()))).await?;
            let c_key = PrivateKey::from_bytes(&c.vault.get("node")?).public_key();
            a.revoke(crate::enrollment::Revoke::Node(c_key)).await?;
            assert!(c.vault.load_bytes("discovery")?.is_none());
            let link = c.network.read().await;
            let stream = link
                .as_ref()
                .ok_or("link")?
                .transport
                .connect("a", Protocol::Link)
                .await?;
            let a_key = PrivateKey::from_bytes(&a.vault.get("node")?).public_key();
            assert!(
                rocky_secure::network::link::Link::open(
                    stream,
                    &c.replica,
                    PrivateKey::from_bytes(&c.vault.get("node")?),
                    c.settings.lock().await.credentials.clone(),
                    Some(a_key),
                )
                .await
                .is_err()
            );
            drop(link);
            assert!(c.vault.load_bytes("discovery")?.is_none());
            let route = "route-learned-in-admitted-session-never-replicated";
            let hinted = PrivateKey::new().public_key();
            a.configure(|settings| {
                settings.learn_contact(
                    &a.vault,
                    ContactHint {
                        node: hinted,
                        routes: vec![("memory".into(), route.into())],
                        trusted: false,
                    },
                    "handover",
                    now()?,
                )
            })
            .await?;
            a.handover
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(hinted);
            pass(&b).await?;
            assert_eq!(
                b.settings.lock().await.peers[&hinted].routes[0].address,
                route
            );
            let b_key = PrivateKey::from_bytes(&b.vault.get("node")?).public_key();
            for id in [secure_node_id(c_key), rocky_core::NodeId([3; 16])] {
                let ContactResponse::Contact { contact } = a
                    .answer(b_key, ContactRequest::Request { node: id })
                    .await?
                else {
                    return Err("response".into());
                };
                assert!(contact.is_none());
            }
            let ContactResponse::Handover { contacts } = a
                .answer(
                    b_key,
                    ContactRequest::Handover {
                        contacts: Vec::new(),
                    },
                )
                .await?
            else {
                return Err("response".into());
            };
            assert!(contacts.iter().all(|contact| contact.node != c_key));
            let a_topic = a
                .settings
                .lock()
                .await
                .discovery_topics(&a.vault, now()?)?
                .0;
            let b_topic = b
                .settings
                .lock()
                .await
                .discovery_topics(&b.vault, now()?)?
                .0;
            assert_eq!(a_topic, b_topic);
            // Replica pages contain neither routes nor discovery material.
            let db = rusqlite::Connection::open(root.path().join("b/rocky.sqlite"))?;
            let dump: String =
                db.query_row("SELECT group_concat(sql) FROM sqlite_master", [], |row| {
                    row.get(0)
                })?;
            assert!(!dump.contains("discovery"));
            assert!(!dump.contains("contact_meta"));
            assert!(!std::fs::read_to_string(&b.path)?.contains("discovery"));
            let state: Value = serde_json::from_slice(
                &b.vault.load_bytes("discovery")?.ok_or("discovery state")?,
            )?;
            let mut needles = vec![serde_json::from_value::<Vec<u8>>(
                state["root"]["value"].clone(),
            )?];
            for value in state["values"].as_object().ok_or("values")?.values() {
                needles.push(serde_json::from_value::<Vec<u8>>(value["value"].clone())?);
            }
            let encoded: Vec<_> = needles
                .iter()
                .map(serde_json::to_vec)
                .collect::<Result<_, _>>()?;
            needles.extend(encoded);
            needles.push(route.as_bytes().to_vec());
            for table in db
                .prepare("SELECT name FROM sqlite_master WHERE type='table'")?
                .query_map([], |row| row.get::<_, String>(0))?
            {
                let table = table?;
                let mut statement =
                    db.prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))?;
                let columns = statement.column_count();
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    for index in 0..columns {
                        let bytes = match row.get_ref(index)? {
                            rusqlite::types::ValueRef::Text(bytes)
                            | rusqlite::types::ValueRef::Blob(bytes) => bytes,
                            _ => continue,
                        };
                        for needle in &needles {
                            assert!(!bytes.windows(needle.len()).any(|part| part == needle));
                            let hex = HEXLOWER.encode(needle);
                            assert!(!bytes.windows(hex.len()).any(|part| part == hex.as_bytes()));
                        }
                    }
                }
            }
            for node in [&a, &b, &c] {
                node.detach(None).await;
            }
            Ok(())
        })
        .await
}

#[tokio::test]
async fn contact_requests_are_bounded_and_a_wrong_node_hash_is_refused() -> Result<(), Failure> {
    struct Misleading(PublicKey);
    impl ContactHandler for Misleading {
        fn answer(
            &self,
            _peer: PublicKey,
            _request: ContactRequest,
        ) -> rocky_secure::network::ContactFuture<'_> {
            Box::pin(async {
                Ok(ContactResponse::Contact {
                    contact: Some(ContactHint {
                        node: self.0,
                        routes: vec![("memory".into(), "false-hint".into())],
                        trusted: false,
                    }),
                })
            })
        }
    }
    tokio::task::LocalSet::new()
        .run_until(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let b = enrolled(&root.path().join("b"), &hub, "b", Some((&a, writer()))).await?;
            let a_key = PrivateKey::from_bytes(&a.vault.get("node")?).public_key();
            for misleading in [false, true] {
                let (mut session, mut serving) = link_sessions(&b, &a).await?;
                let node = a.clone();
                let task = tokio::task::spawn_local(async move {
                    if misleading {
                        serving
                            .serve_with_contacts(&node.replica, &Misleading(a_key))
                            .await?;
                    } else {
                        serving.serve_with_contacts(&node.replica, &*node).await?;
                    }
                    Ok::<_, Failure>(())
                });
                if misleading {
                    assert!(
                        session
                            .exchange_contacts(ContactRequest::Request {
                                node: rocky_core::NodeId([4; 16])
                            })
                            .await
                            .is_err()
                    );
                } else {
                    for _ in 0..8 {
                        let ContactResponse::Contact { contact } = session
                            .exchange_contacts(ContactRequest::Request {
                                node: rocky_core::NodeId([4; 16]),
                            })
                            .await?
                        else {
                            return Err("contact response".into());
                        };
                        assert!(contact.is_none());
                    }
                    assert!(
                        session
                            .exchange_contacts(ContactRequest::Request {
                                node: rocky_core::NodeId([4; 16])
                            })
                            .await
                            .is_err()
                    );
                }
                session.close().await?;
                task.await??;
            }
            for node in [&a, &b] {
                node.detach(None).await;
            }
            Ok(())
        })
        .await
}

#[tokio::test]
async fn a_needed_partition_reaches_its_keyless_custody_peer_within_two_passes()
-> Result<(), Failure> {
    tokio::task::LocalSet::new().run_until(async {
        let schema = Schema::parse(r#"{"application":"mesh_partition","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"list","type":"text","not_null":true},{"name":"key","type":"text","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["list","key"],"partition_by":["list"]}]}"#)?;
        let root = tempfile::tempdir()?;
        let hub = Arc::new(Hub::default());
        let a = enrolled_schema(&root.path().join("a"), &hub, "a", None, &schema).await?;
        let reader = Profile::Reader { scopes: ["items".into()].into() };
        let b = enrolled_schema(&root.path().join("b"), &hub, "b", Some((&a, reader.clone())), &schema).await?;
        let c = enrolled_schema(&root.path().join("c"), &hub, "c", Some((&a, reader)), &schema).await?;
        let d = enrolled_schema(&root.path().join("d"), &hub, "d", Some((&a, Profile::Custody { scopes: ["items".into()].into() })), &schema).await?;
        let values = json!([{"type":"text","value":"only-custody"}]);
        command(&a, json!({"type":"partition_create","table":"items","values":values})).await?;
        let b_key = PrivateKey::from_bytes(&b.vault.get("node")?).public_key();
        let shared = command(&a, json!({"type":"partition_share","table":"items","values":values,"recipients":[b_key]})).await?;
        command(&b, json!({"type":"partition_install","table":"items","values":values,"envelope":shared["envelopes"][0]["envelope"],"sender":shared["sender"]})).await?;
        command(&d, json!({"type":"partition_register","table":"items","values":values})).await?;
        command(&a, json!({"type":"sql","sql":"BEGIN"})).await?;
        let id = command(&a, json!({"type":"next_id","table":"items","partition_values":values})).await?["id"].clone();
        command(&a, json!({"type":"sql","sql":"INSERT INTO items(list,key,title,id) VALUES('only-custody','k','custody row',?)","values":[{"type":"integer","value":id}]})).await?;
        command(&a, json!({"type":"sql","sql":"COMMIT"})).await?;
        pass(&d).await?;
        a.detach(None).await;
        let d_key = contact(&b, &d).await?;
        let c_key = contact(&b, &c).await?;
        let a_key = PrivateKey::from_bytes(&a.vault.get("node")?).public_key();
        b.configure(|settings| { settings.remove_peer(a_key)?; settings.contact_meta.get_mut(&c_key).ok_or("local")?.local = true; Ok(()) }).await?;
        pass(&b).await?;
        pass(&b).await?;
        {
        let reached = b.reached()?;
        assert!(reached.get(&c_key).is_some_and(|last| !last.refused.is_empty() || last.error.is_some()));
        let held = &reached.get(&d_key).ok_or("custody was not reached")?.held;
        assert!(b.scopes().iter().filter(|scope| !b.domain().partitioned_table(scope)).all(|scope| held.contains(scope)));
        assert!(hub.dials_to("d") > 0);
        }
        let page = command(&b, json!({"type":"read","query":{"sql":"SELECT title FROM items","max_rows":8}})).await?;
        assert_eq!(page["rows"][0][0]["value"], "custody row");
        for node in [&a, &b, &c, &d] { node.detach(None).await; }
        Ok(())
    }).await
}

async fn command(node: &Node, request: Value) -> Result<Value, Failure> {
    let client = node.client(1)?;
    Box::pin(node.dispatch(&client, &request)).await
}

#[tokio::test(start_paused = true)]
async fn handover_survives_an_earlier_successful_pass() -> Result<(), Failure> {
    tokio::task::LocalSet::new()
        .run_until(change_driven::frozen(async {
            let root = tempfile::tempdir()?;
            let hub = Arc::new(Hub::default());
            let a = enrolled(&root.path().join("a"), &hub, "a", None).await?;
            let c = enrolled(&root.path().join("c"), &hub, "c", Some((&a, writer()))).await?;
            let c_key = contact(&a, &c).await?;
            pass(&a).await?;
            pass(&a).await?;
            let b = enrolled(&root.path().join("b"), &hub, "b", Some((&a, writer()))).await?;
            assert_eq!(b.settings.lock().await.peers.len(), 1);
            pass(&b).await?;
            assert_eq!(
                b.settings.lock().await.contact_meta[&c_key].source,
                "handover"
            );
            for node in [&a, &b, &c] {
                node.detach(None).await;
            }
            Ok(())
        }))
        .await
}
