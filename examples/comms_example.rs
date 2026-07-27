use auth67::{adapters::comms::CommsAdapter, ports::comms::CommsPort};
use tracing::{error, info};

const SMS_FROM: &str = "Auth67";
const SMS_TO: &str = "+4741387142";
const SMS_MESSAGE: &str = "Hello!";

const EMAIL_FROM: &str = "auth67@resend.dev"; // TODO add your own domain
const EMAIL_TO: &str = "amund.fremming@gmail.com";
const EMAIL_SUBJECT: &str = "Hello from Auth67!";
const EMAIL_HTML: &str = "<p>Welcome to Auth67!</p>";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let elks_username = std::env::var("ELKS_USERNAME").expect("ELKS_USERNAME not set");
    let elks_password = std::env::var("ELKS_PASSWORD").expect("ELKS_PASSWORD not set");
    let resend_api_key = std::env::var("RESEND_API_KEY").expect("RESEND_API_KEY not set");

    let comms = CommsAdapter::new(elks_username, elks_password, resend_api_key);

    // SMS example
    match comms.send_sms(SMS_FROM, SMS_TO, SMS_MESSAGE).await {
        Ok(response) => {
            info!(id = %response.id, status = %response.status, cost = %response.cost, "SMS sent successfully");
        }
        Err(e) => {
            error!(error = %e, "Failed to send SMS");
        }
    }

    // Email example
    match comms
        .send_email(
            EMAIL_FROM,
            &[EMAIL_TO],
            EMAIL_SUBJECT,
            Some(EMAIL_HTML),
            None,
        )
        .await
    {
        Ok(response) => {
            info!(id = %response.id, "Email sent successfully");
        }
        Err(e) => {
            error!(error = %e, "Failed to send email");
        }
    }
}
