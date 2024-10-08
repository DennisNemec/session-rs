use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::modules::auth::AuthError;

use super::{TOAuthGetPersonInfo, TPerson};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePerson {
    names: Vec<GoogleName>,
    email_addresses: Vec<GoogleMail>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleName {
    family_name: String,
    given_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GoogleMail {
    value: String,
    metadata: GoogleMailMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GoogleMailMetadata {
    primary: Option<bool>
}

impl TPerson for GooglePerson {
    fn get_mail(&self) -> String {
        let primary_mail: Vec<GoogleMail> = self
            .email_addresses
            .clone()
            .into_iter()
            .filter(|mail| mail.metadata.primary.is_some())
            .collect();

        primary_mail[0].value.clone()
    }

    fn get_first_name(&self) -> String {
        self.names[0].given_name.clone()
    }

    fn get_last_name(&self) -> String {
        self.names[0].family_name.clone()
    }
}

#[derive(Clone)]
pub struct GooglePersonEndpoint {
    url: String,
}

impl GooglePersonEndpoint {
    pub fn new(fields: Vec<&str>) -> Self {
        Self {
            url: format!(
                "https://people.googleapis.com/v1/people/me?personFields={}",
                fields.join(",")
            )
            .to_string(),
        }
    }
}

#[async_trait]
impl TOAuthGetPersonInfo for GooglePersonEndpoint {
    type Error = AuthError;
    type Person = GooglePerson;

    async fn get_information(&self, access_token: String) -> Result<Self::Person, Self::Error> {
        let client = Client::new();
        let req: reqwest::Request = client
            .get(self.url.clone())
            .bearer_auth(access_token)
            .build()
            .unwrap();

        let user_result = client.execute(req).await.map_err(Self::Error::HttpError)?;
        let response_text = user_result.text().await.map_err(Self::Error::HttpError)?;

        Ok(
            serde_json::from_str(&response_text).map_err(Self::Error::Json)?
        )
    }
}
