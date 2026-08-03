use async_trait::async_trait;

use crate::models::comms::{SendEmailRequest, SendEmailResponse, SendSmsResponse};
use crate::ports::comms::CommsPort;

pub struct CommsAdapter {
    elks_username: String,
    elks_password: String,
    resend_api_key: String,
}

impl CommsAdapter {
    pub fn new(elks_username: String, elks_password: String, resend_api_key: String) -> Self {
        Self {
            elks_username,
            elks_password,
            resend_api_key,
        }
    }
}

#[async_trait]
impl CommsPort for CommsAdapter {
    async fn send_sms(
        &self,
        from: &str,
        to: &str,
        message: &str,
    ) -> Result<SendSmsResponse, reqwest::Error> {
        let client = reqwest::Client::new();

        let response = client
            .post("https://api.46elks.com/a1/sms")
            .basic_auth(&self.elks_username, Some(&self.elks_password))
            .form(&[("from", from), ("to", to), ("message", message)])
            .send()
            .await?
            .json::<SendSmsResponse>()
            .await?;

        Ok(response)
    }

    async fn send_email(
        &self,
        from: &str,
        to: &[&str],
        subject: &str,
        html: Option<&str>,
        text: Option<&str>,
    ) -> Result<SendEmailResponse, reqwest::Error> {
        let client = reqwest::Client::new();

        let request = SendEmailRequest {
            from: from.to_string(),
            to: to.iter().map(|s| s.to_string()).collect(),
            subject: subject.to_string(),
            html: html.map(|s| s.to_string()),
            text: text.map(|s| s.to_string()),
        };

        let response = client
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.resend_api_key)
            .json(&request)
            .send()
            .await?;

        let body = response.text().await?;
        println!("📧 Resend response: {}", body);

        let parsed: SendEmailResponse =
            serde_json::from_str(&body).expect("Failed to parse Resend response");
        Ok(parsed)
    }
}
