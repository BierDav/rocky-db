//! A trusted node's composed coordinated log: it ends tips' logs with
//! their seals and acknowledges their terminal entries. Rocky orders no
//! writes through it; applications coordinate their own.
use super::*;
use rocky_core::DomainLog;

impl Node {
    /// Makes this device a trusted node of its domain's coordinated logs, or
    /// ends that with `None`. The log is the application's; Rocky never
    /// closes it.
    pub fn coordinate(self: &Arc<Self>, log: Option<Arc<dyn DomainLog>>) {
        self.replica.set_domain_log(log);
    }
}
impl Node {
    /// Whether this device is a trusted node with a composed log, and the
    /// log of the tip it follows.
    pub(super) async fn coordinated_status(&self) -> Result<Value, Failure> {
        let log = self.replica.followed_log(self.domain().scope).await;
        Ok(json!({
            "trusted": self.replica.domain_log().is_some(),
            "tip": HEXLOWER.encode(&log.tip.0),
        }))
    }
}
