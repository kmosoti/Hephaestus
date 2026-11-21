//! Native-IPv6 HTTP/JSON push webhook sink adapter.

use hephaestus_store::{BoxFuture, PushWebhookEvent, StoreError, WebhookSink};
use std::time::Duration;

/// HTTP POST JSON implementation of [`WebhookSink`].
#[derive(Clone)]
pub struct HttpWebhookSink {
    url: String,
    client: reqwest::Client,
}

impl HttpWebhookSink {
    /// Creates an HTTP webhook sink targeting `url`.
    pub fn new(url: impl Into<String>) -> Result<Self, StoreError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| StoreError::Backend(format!("webhook reqwest client: {e}")))?;
        Ok(Self {
            url: url.into(),
            client,
        })
    }
}

impl WebhookSink for HttpWebhookSink {
    fn notify_push<'a>(
        &'a self,
        event: &'a PushWebhookEvent,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let resp = self
                .client
                .post(&self.url)
                .json(event)
                .send()
                .await
                .map_err(|e| StoreError::Backend(format!("webhook post failed: {e}")))?;
            Ok(resp.status().is_success())
        })
    }
}

/// No-op webhook sink used when no CI notification URL is configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopWebhookSink;

impl WebhookSink for NoopWebhookSink {
    fn notify_push<'a>(
        &'a self,
        _event: &'a PushWebhookEvent,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async { Ok(false) })
    }
}
