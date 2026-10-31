use super::*;
use rocky_core::{ApplicationManifest, FieldOrdinals};

type Fields = BTreeMap<u32, serde_bytes::ByteBuf>;

#[derive(Serialize, Deserialize)]
struct Write(
    serde_bytes::ByteArray<32>,
    Option<Fields>,
    Option<Fields>,
    BTreeSet<u32>,
);

#[derive(Serialize, Deserialize)]
struct Carry {
    proof: (usize, i64, serde_bytes::ByteArray<32>),
    stamps: BTreeMap<u32, crate::replica::Stamp>,
    #[serde(with = "serde_bytes")]
    moved_from: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct Bundle {
    version: u8,
    carried: BTreeMap<serde_bytes::ByteArray<32>, Carry>,
    authors: BTreeMap<u32, PublicKey>,
    origins: Vec<serde_bytes::ByteBuf>,
    headers: BTreeMap<serde_bytes::ByteArray<32>, serde_bytes::ByteBuf>,
    bindings: BTreeMap<serde_bytes::ByteArray<32>, serde_bytes::ByteBuf>,
    membership: Option<Membership>,
    writes: Vec<Write>,
    intent: Option<rocky_core::replay::Intent>,
    outcome: Option<rocky_core::replay::OutcomeRecord>,
}

fn ordinal(fields: &FieldOrdinals<'_>, field: Commitment) -> Result<u32, Error> {
    fields
        .ordinal(field)
        .ok_or_else(|| denied("frame field is outside its source table schema"))
}

fn field(fields: &FieldOrdinals<'_>, ordinal: u32) -> Result<Commitment, Error> {
    fields
        .field(ordinal)
        .ok_or_else(|| denied("frame ordinal is outside its source table schema"))
}

fn compact_image(
    image: Option<RowFields>,
    fields: &FieldOrdinals<'_>,
) -> Result<Option<Fields>, Error> {
    image
        .map(|image| {
            image
                .into_iter()
                .map(|(key, value)| Ok((ordinal(fields, key)?, value.into())))
                .collect()
        })
        .transpose()
}

fn expand_image(
    image: Option<Fields>,
    fields: &FieldOrdinals<'_>,
) -> Result<Option<RowFields>, Error> {
    image
        .map(|image| {
            image
                .into_iter()
                .map(|(key, value)| Ok((field(fields, key)?, value.into_vec())))
                .collect()
        })
        .transpose()
}

pub(super) fn compact(
    bytes: &[u8],
    definition: &ApplicationManifest,
    scope: ResourceScope,
) -> Result<Vec<u8>, Error> {
    let envelope: WitnessBody = decode(bytes)?;
    let body: BundleBody = decode(&envelope.body)?;
    if envelope.version != 1 {
        return Err(denied("unsupported bundle version"));
    }
    let fields = definition
        .field_ordinals(scope.table)
        .map_err(|_| denied("source table schema is not installed"))?;
    let mut writes = Vec::with_capacity(body.writes.len());
    for write in body.writes {
        if write.change.scope != scope {
            return Err(denied("frame write scope differs from its header"));
        }
        writes.push(Write(
            write.change.row.into(),
            compact_image(write.change.before, &fields)?,
            compact_image(write.change.after, &fields)?,
            write
                .assigned
                .into_iter()
                .map(|key| ordinal(&fields, key))
                .collect::<Result<_, _>>()?,
        ));
    }
    let mut authors = BTreeMap::new();
    let mut origins = Vec::<serde_bytes::ByteBuf>::new();
    let mut origin_ids = BTreeMap::new();
    let mut headers = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    let carried = body
        .carried
        .into_iter()
        .map(|(row, carried)| {
            for (author, signer) in &carried.authors {
                if authors
                    .insert(*author, *signer)
                    .is_some_and(|old| old != *signer)
                {
                    return Err(denied("carried author legend names conflicting signers"));
                }
            }
            let parts = carried.proof.wire_parts()?;
            let (origin, identity, provenance, set, header) = (
                parts.origin,
                parts.identity,
                parts.provenance,
                parts.bindings,
                parts.header,
            );
            let (binding_digest, header_digest) =
                crate::replica::moves::CreationProof::wire_references(&origin)?;
            let index = *origin_ids.entry(origin.clone()).or_insert_with(|| {
                let index = origins.len();
                origins.push(origin.into());
                index
            });
            headers.insert(header_digest.into(), header.into());
            bindings.insert(binding_digest.into(), set.into());

            Ok((
                row.into(),
                Carry {
                    proof: (index, identity, provenance.into()),
                    stamps: carried
                        .stamps
                        .into_iter()
                        .map(|(key, stamp)| Ok((ordinal(&fields, key)?, stamp)))
                        .collect::<Result<_, Error>>()?,
                    moved_from: carried.moved_from,
                },
            ))
        })
        .collect::<Result<_, Error>>()?;
    encode(&WitnessBody {
        version: 1,
        body: encode(&Bundle {
            version: if body.version == 5 {
                6
            } else {
                body.version.saturating_add(1)
            },
            carried,
            authors,
            origins,
            headers,
            bindings,
            membership: body.membership,
            writes,
            intent: body.intent,
            outcome: body.outcome,
        })?,
        creations: envelope.creations,
    })
}

pub(super) fn expand(
    bytes: &[u8],
    definition: &ApplicationManifest,
    scope: ResourceScope,
) -> Result<RowPayload, Error> {
    let envelope: WitnessBody = decode(bytes)?;
    RowPayload::check_formats(bytes)?;
    if envelope.creations.len() > 32
        || envelope
            .creations
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(denied("invalid creation witness envelope"));
    }
    let body: Bundle = decode(&envelope.body)?;
    if envelope.version != 1 || body.version != 6 {
        return Err(denied("unsupported bundle version"));
    }
    if let Some(intent) = &body.intent {
        // An intent is one bundle member and carries no rows.
        if !body.writes.is_empty() || body.membership.is_none() || !body.carried.is_empty() {
            return Err(denied("an intent frame carries rows"));
        }
        intent.check().map_err(denied)?;
    }
    if let Some(outcome) = &body.outcome {
        // An outcome record stands alone in its frame.
        if !body.writes.is_empty()
            || body.membership.is_some()
            || body.intent.is_some()
            || !body.carried.is_empty()
        {
            return Err(denied("an outcome frame carries more than its record"));
        }
        outcome.check().map_err(denied)?;
    }
    let fields = definition
        .field_ordinals(scope.table)
        .map_err(|_| denied("source table schema is not installed"))?;
    let writes = body
        .writes
        .into_iter()
        .map(|Write(row, before, after, assigned)| {
            Ok(RowWrite {
                change: RowChange {
                    scope,
                    row: row.into_array(),
                    before: expand_image(before, &fields)?,
                    after: expand_image(after, &fields)?,
                },
                assigned: assigned
                    .into_iter()
                    .map(|key| field(&fields, key))
                    .collect::<Result<_, Error>>()?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let mut used_authors = BTreeSet::new();
    let mut used_origins = BTreeSet::new();
    let mut used_headers = BTreeSet::new();
    let mut used_bindings = BTreeSet::new();
    if body.origins.iter().collect::<BTreeSet<_>>().len() != body.origins.len() {
        return Err(denied("carried proof legend repeats an origin"));
    }
    let carried = body
        .carried
        .into_iter()
        .map(|(row, carried)| {
            let mut authors = BTreeMap::new();
            for author in carried.stamps.values().map(|stamp| stamp.author) {
                authors.insert(
                    author,
                    *body
                        .authors
                        .get(&author)
                        .ok_or_else(|| denied("carried stamp lacks its signer"))?,
                );
                used_authors.insert(author);
            }
            let (index, identity, provenance) = carried.proof;
            let origin = body
                .origins
                .get(index)
                .ok_or_else(|| denied("carried proof lacks an origin"))?;
            let (binding_digest, header_digest) =
                crate::replica::moves::CreationProof::wire_references(origin)?;
            let set = body
                .bindings
                .get(&serde_bytes::ByteArray::new(binding_digest))
                .ok_or_else(|| denied("carried proof lacks its bindings"))?;
            let header = body
                .headers
                .get(&serde_bytes::ByteArray::new(header_digest))
                .ok_or_else(|| denied("carried proof lacks its header"))?;
            let proof = crate::replica::moves::CreationProof::from_wire_parts(
                origin,
                identity,
                provenance.into_array(),
                set,
                header,
            )?;
            used_origins.insert(index);
            used_headers.insert(header_digest);
            used_bindings.insert(binding_digest);

            Ok((
                row.into_array(),
                crate::replica::moves::Carried {
                    proof,
                    authors,
                    stamps: carried
                        .stamps
                        .into_iter()
                        .map(|(key, stamp)| Ok((field(&fields, key)?, stamp)))
                        .collect::<Result<_, Error>>()?,
                    moved_from: carried.moved_from,
                },
            ))
        })
        .collect::<Result<_, Error>>()?;
    if used_authors.len() != body.authors.len()
        || used_origins.len() != body.origins.len()
        || used_headers.len() != body.headers.len()
        || used_bindings.len() != body.bindings.len()
    {
        return Err(denied("carried proof legend has unused entries"));
    }
    Ok(RowPayload {
        #[cfg(test)]
        source: Some(definition.clone()),
        proofs: BTreeMap::new(),
        carried,
        membership: body.membership,
        writes,
        intent: body.intent,
        outcome: body.outcome,
        creations: envelope.creations,
    })
}

#[cfg(test)]
pub(super) fn compact_test(
    bytes: &[u8],
    definition: &ApplicationManifest,
    scope: ResourceScope,
) -> Result<Vec<u8>, Error> {
    let mut envelope: WitnessBody = decode(bytes)?;
    let mut body: BundleBody = decode(&envelope.body)?;
    let fields = definition
        .field_ordinals(scope.table)
        .map_err(|_| denied("source table schema is not installed"))?;
    let mut invalid = Vec::new();
    for (index, write) in body.writes.iter_mut().enumerate() {
        let wrong_scope = write.change.scope != scope;
        write.change.scope = scope;
        let mut before = wrong_scope;
        let mut after = wrong_scope;
        for (image, flag) in [
            (&mut write.change.before, &mut before),
            (&mut write.change.after, &mut after),
        ] {
            if let Some(image) = image {
                image.retain(|field, _| {
                    let valid = fields.ordinal(*field).is_some();
                    *flag |= !valid;
                    valid
                });
            }
        }
        let mut assigned = false;
        write.assigned.retain(|field| {
            let valid = fields.ordinal(*field).is_some();
            assigned |= !valid;
            valid
        });
        invalid.push((index, before, after, assigned));
    }
    envelope.body = encode(&body)?;
    let bytes = compact(&encode(&envelope)?, definition, scope)?;
    let mut envelope: WitnessBody = decode(&bytes)?;
    let mut body: Bundle = decode(&envelope.body)?;
    for (index, before, after, assigned) in invalid {
        let Write(_, old, new, mask) = &mut body.writes[index];
        if before && let Some(old) = old {
            old.insert(u32::MAX, vec![0].into());
        }
        if after && let Some(new) = new {
            new.insert(u32::MAX, vec![0].into());
        }
        if assigned {
            mask.insert(u32::MAX);
        }
    }
    envelope.body = encode(&body)?;
    encode(&envelope)
}
