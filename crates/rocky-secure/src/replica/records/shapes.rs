//! File-local field sets let seals find implicit SQL defaults by index.
use super::*;

pub(in crate::replica) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS secure_record_shapes(id INTEGER PRIMARY KEY AUTOINCREMENT,fields BLOB NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS secure_record_shape_fields(shape BLOB NOT NULL,field BLOB NOT NULL,PRIMARY KEY(shape,field)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS secure_scope_shapes(scope INTEGER NOT NULL,shape BLOB NOT NULL,records INTEGER NOT NULL,PRIMARY KEY(scope,shape)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS secure_rows_shape ON secure_rows(scope,shape,row)",
    "CREATE TRIGGER IF NOT EXISTS secure_shapes_insert AFTER INSERT ON secure_rows BEGIN UPDATE secure_scope_shapes SET records=records+1 WHERE scope=NEW.scope AND shape=NEW.shape; INSERT INTO secure_scope_shapes SELECT NEW.scope,NEW.shape,1 WHERE NOT EXISTS(SELECT 1 FROM secure_scope_shapes WHERE scope=NEW.scope AND shape=NEW.shape); END",
    "CREATE TRIGGER IF NOT EXISTS secure_shapes_delete AFTER DELETE ON secure_rows BEGIN UPDATE secure_scope_shapes SET records=records-1 WHERE scope=OLD.scope AND shape=OLD.shape; DELETE FROM secure_scope_shapes WHERE scope=OLD.scope AND shape=OLD.shape AND records=0; END",
    "CREATE TRIGGER IF NOT EXISTS secure_shapes_update AFTER UPDATE OF fields ON secure_rows WHEN OLD.shape IS NOT NEW.shape BEGIN UPDATE secure_scope_shapes SET records=records-1 WHERE scope=OLD.scope AND shape=OLD.shape; DELETE FROM secure_scope_shapes WHERE scope=OLD.scope AND shape=OLD.shape AND records=0; UPDATE secure_scope_shapes SET records=records+1 WHERE scope=NEW.scope AND shape=NEW.shape; INSERT INTO secure_scope_shapes SELECT NEW.scope,NEW.shape,1 WHERE NOT EXISTS(SELECT 1 FROM secure_scope_shapes WHERE scope=NEW.scope AND shape=NEW.shape); END",
];

impl<A: RowApplication> Inner<A> {
    pub(in crate::replica) async fn record_shape(
        &self,
        fields: Vec<Commitment>,
        allocate: bool,
    ) -> Result<i64, Error> {
        if let Some(id) = self.dictionary().shape_ids.get(&fields).copied() {
            return Ok(id);
        }
        let bytes = encode(&fields)?;
        let found = collect_rows(
            self.conn
                .query(
                    "SELECT id FROM secure_record_shapes WHERE fields=?",
                    [bytes.clone()],
                )
                .await?,
        )
        .await?;
        let id = match found.first().map(Vec::as_slice) {
            Some([SqlValue::Integer(id)]) => *id,
            None if allocate => {
                self.conn
                    .execute(
                        "INSERT INTO secure_record_shapes(fields) VALUES(?)",
                        [bytes.clone()],
                    )
                    .await?;
                let found = collect_rows(
                    self.conn
                        .query(
                            "SELECT id FROM secure_record_shapes WHERE fields=?",
                            [bytes],
                        )
                        .await?,
                )
                .await?;
                match found.first().map(Vec::as_slice) {
                    Some([SqlValue::Integer(id)]) => *id,
                    _ => return Err(Error::Corrupt("interned row shape".into())),
                }
            }
            _ => return Err(Error::Corrupt("stored row shape is missing".into())),
        };
        if allocate && found.is_empty() {
            for field in &fields {
                self.conn
                    .execute(
                        "INSERT INTO secure_record_shape_fields VALUES(?,?)",
                        [encode(&id)?, field.to_vec()],
                    )
                    .await?;
            }
        }
        let mut dictionary = self.dictionary();
        dictionary.shapes.insert(id, fields.clone());
        dictionary.shape_ids.insert(fields, id);
        Ok(id)
    }

    pub(in crate::replica) async fn shape_fields(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<Commitment>, Error> {
        let id: i64 = decode(bytes)?;
        if id <= 0 || encode(&id)? != bytes {
            return Err(Error::Corrupt("stored row shape id".into()));
        }
        if let Some(fields) = self.dictionary().shapes.get(&id).cloned() {
            return Ok(fields);
        }
        let found = collect_rows(
            self.conn
                .query("SELECT fields FROM secure_record_shapes WHERE id=?", [id])
                .await?,
        )
        .await?;
        let Some([SqlValue::Blob(bytes)]) = found.first().map(Vec::as_slice) else {
            return Err(Error::Corrupt("unknown row shape".into()));
        };
        let fields: Vec<Commitment> = decode(bytes)?;
        if id <= 0 || fields.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Corrupt("invalid row shape".into()));
        }
        let members = collect_rows(
            self.conn
                .query(
                    "SELECT field FROM secure_record_shape_fields WHERE shape=? ORDER BY field",
                    [encode(&id)?],
                )
                .await?,
        )
        .await?;
        let expected: Vec<_> = fields
            .iter()
            .map(|field| vec![SqlValue::Blob(field.to_vec())])
            .collect();
        if members != expected {
            return Err(Error::Corrupt(
                "row shape members differ from legend".into(),
            ));
        }
        let mut dictionary = self.dictionary();
        dictionary.shapes.insert(id, fields.clone());
        dictionary.shape_ids.insert(fields.clone(), id);
        Ok(fields)
    }
}
