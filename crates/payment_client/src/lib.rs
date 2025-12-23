use biz_api::{InvoiceDraft, PaymentProvider};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct HttpPaymentProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct EnsureCustomerRequest<'a> {
    external_customer_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct EnsureCustomerResponse {
    id: String,
}

#[derive(Debug, Serialize)]
struct CreateInvoiceRequest<'a> {
    customer_id: &'a str,
    invoice: &'a InvoiceDraft,
}

#[derive(Debug, Deserialize)]
struct CreateInvoiceResponse {
    id: String,
}

impl HttpPaymentProvider {
    pub fn from_env() -> Result<Self, String> {
        let base_url = std::env::var("PAYMENT_BACKEND_URL")
            .map_err(|_| "PAYMENT_BACKEND_URL not set".to_string())?;

        if base_url.trim().is_empty() {
            return Err("PAYMENT_BACKEND_URL is empty".to_string());
        }

        let api_key = std::env::var("PAYMENT_BACKEND_API_KEY").ok();

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("failed to build payment backend http client: {e}"))?;

        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }

    fn auth_header(
        &self,
        req: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        if let Some(ref key) = self.api_key {
            req.bearer_auth(key)
        } else {
            req
        }
    }
}

impl PaymentProvider for HttpPaymentProvider {
    type Error = String;

    fn ensure_customer(&self, external_customer_id: &str) -> Result<String, Self::Error> {
        let url = format!("{}/customers", self.base_url.trim_end_matches('/'));
        let body = EnsureCustomerRequest {
            external_customer_id,
        };

        let req = self.client.post(&url).json(&body);
        let req = self.auth_header(req);

        let resp = req
            .send()
            .map_err(|e| format!("failed to call payment backend customers endpoint: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!(
                "payment backend customers endpoint returned status {}",
                resp.status()
            ));
        }

        let parsed: EnsureCustomerResponse = resp
            .json()
            .map_err(|e| format!("failed to parse payment backend customers response: {e}"))?;

        Ok(parsed.id)
    }

    fn create_invoice(
        &self,
        provider_customer_id: &str,
        draft: &InvoiceDraft,
    ) -> Result<String, Self::Error> {
        let url = format!("{}/invoices", self.base_url.trim_end_matches('/'));
        let body = CreateInvoiceRequest {
            customer_id: provider_customer_id,
            invoice: draft,
        };

        let req = self.client.post(&url).json(&body);
        let req = self.auth_header(req);

        let resp = req
            .send()
            .map_err(|e| format!("failed to call payment backend invoices endpoint: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!(
                "payment backend invoices endpoint returned status {}",
                resp.status()
            ));
        }

        let parsed: CreateInvoiceResponse = resp
            .json()
            .map_err(|e| format!("failed to parse payment backend invoices response: {e}"))?;

        Ok(parsed.id)
    }
}
