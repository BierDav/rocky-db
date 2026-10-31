//! Exact, tip-authenticated schema catalog records; the supplier grants no authority.
use crate::{Failure, domain::Domain, enrollment::Settings, schema::Schema};
use rocky_core::{Commitment, TipId};
use serde::{Deserialize, Serialize};

pub(crate) const PROTOCOL: &[u8] = b"rocky.sdk.tip-schema.v1\n";
const FORMAT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub format: u32,
    pub generation: u32,
    pub schema: Schema,
}
impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            format: u32,
            generation: u32,
            schema: serde_json::Value,
        }
        let raw = Raw::deserialize(deserializer)?;
        use serde::de::Error;
        if raw.format != FORMAT || raw.generation == 0 {
            return Err(D::Error::custom("unsupported tip schema record"));
        }
        if raw.schema.get("migrations").is_some() {
            return Err(D::Error::custom(
                "a tip schema record cannot contain migrations",
            ));
        }
        let schema = Schema::parse(&raw.schema.to_string()).map_err(D::Error::custom)?;
        Ok(Self {
            format: raw.format,
            generation: raw.generation,
            schema,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub tip: TipId,
    pub manifest: Commitment,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub manifest: Commitment,
}
impl Record {
    pub fn new(schema: &Schema, generation: u32) -> Self {
        let mut schema = schema.clone();
        schema.migrations.clear();
        Self {
            format: FORMAT,
            generation,
            schema,
        }
    }
    pub fn bytes(&self) -> Result<Vec<u8>, Failure> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > rocky_core::MAX_DEFINITION_BYTES {
            return Err("tip schema quota".into());
        }
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() > rocky_core::MAX_DEFINITION_BYTES {
            return Err("tip schema quota".into());
        }
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        if value["format"].as_u64() != Some(u64::from(FORMAT)) {
            return Err("unsupported tip schema record format".into());
        }
        if value["schema"].get("migrations").is_some() {
            return Err("a tip schema record cannot contain migrations".into());
        }
        let record: Self = serde_json::from_value(value)?;
        // Parsing the portable schema performs all definition and profile checks.
        Schema::parse(&serde_json::to_string(&record.schema)?)?;
        if record.generation == 0 {
            return Err("invalid tip schema generation".into());
        }
        Ok(record)
    }
    pub fn domain(&self, settings: &Settings, expected: Commitment) -> Result<Domain, Failure> {
        if self.schema.application != settings.schema.application {
            return Err("tip schema is another application".into());
        }
        let domain = Domain::at(
            &self.schema,
            *settings.publisher.as_bytes(),
            settings.mesh,
            settings.domain,
            self.generation,
        )?;
        if domain.manifest().hash() != expected {
            return Err("tip schema commitment mismatch".into());
        }
        Ok(domain)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bootstrap {
    pub graph: rocky_credentials::TipGraph,
    pub followed: Option<String>,
}
impl Bootstrap {
    pub fn verify(&self, settings: &Settings) -> Result<(), Failure> {
        let genesis = settings.manifest()?;
        let root = genesis.verify(settings.publisher)?;
        if !genesis.endorsement().chain.0.is_empty()
            || self.graph.genesis_schema != root.hash()
            || self.graph.scope != settings.domain()?.scope
        {
            return Err("enrollment graph differs from the domain root".into());
        }
        for seal in &self.graph.seals {
            seal.verify(settings.publisher, &self.graph)?;
        }
        for opening in &self.graph.openings {
            opening.verify(settings.publisher, &self.graph)?;
        }
        for movement in &self.graph.moves {
            movement.verify(settings.publisher, &self.graph)?;
        }
        for minimum in &self.graph.genesis_lines {
            minimum.verify(settings.publisher, &self.graph)?;
        }
        for finality in &self.graph.finalities {
            self.graph
                .verify_finality(finality, settings.publisher, None)?;
        }
        for checkpoint in &self.graph.checkpoints {
            checkpoint.verify(settings.publisher, &self.graph)?;
        }
        let mut graph = self.graph.clone();
        graph.exclude_revoked(&settings.revocations)?;
        let tip = match &self.followed {
            Some(name) => graph
                .bookmark(name)?
                .ok_or("enrollment bookmark does not resolve")?,
            None => graph.genesis(),
        };
        if graph.schema(tip)? != settings.domain()?.manifest().hash() {
            return Err("enrollment record differs from its followed tip".into());
        }
        Ok(())
    }
}
impl Settings {
    pub(crate) fn verify_schema(&self) -> Result<(), Failure> {
        let root = self.manifest()?.verify(self.publisher)?;
        let domain = self.domain()?;
        if root.app != domain.manifest().app || self.generation == 0 {
            return Err("invalid installed schema context".into());
        }
        if let Some(bootstrap) = &self.bootstrap {
            bootstrap.verify(self)?;
        }
        Ok(())
    }
    pub(crate) fn schema_bootstrap(&self) -> Result<Bootstrap, Failure> {
        match &self.bootstrap {
            Some(bootstrap) => Ok(bootstrap.clone()),
            None if self.manifest()?.verify(self.publisher)?.hash()
                == self.domain()?.manifest().hash() =>
            {
                Ok(Bootstrap {
                    graph: rocky_credentials::TipGraph::new(
                        self.domain()?.scope,
                        self.domain()?.manifest().hash(),
                    ),
                    followed: None,
                })
            }
            None => Err("enrollment needs the current tip graph".into()),
        }
    }
}
