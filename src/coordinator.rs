use std::net::SocketAddr;

use revault_net::{
    message::coordinator::{GetSpendTx, SpendTx},
    noise::{PublicKey, SecretKey},
    transport::KKTransport,
};

use revault_tx::bitcoin::{OutPoint, Transaction};

const COORDINATOR_CLIENT_RETRIES: usize = 3;

pub struct CoordinatorClient {
    host: SocketAddr,
    our_noise_secret_key: SecretKey,
    pub_key: PublicKey,
    /// How many times the client will try again
    /// to send a request to coordinator upon failure
    retries: usize,
}

impl CoordinatorClient {
    pub fn new(our_noise_secret_key: SecretKey, host: SocketAddr, pub_key: PublicKey) -> Self {
        Self {
            host,
            our_noise_secret_key,
            pub_key,
            retries: COORDINATOR_CLIENT_RETRIES,
        }
    }

    /// Wrapper to retry a request sent to coordinator upon IO failure
    /// according to the configured number of retries.
    fn retry<T, R: Fn() -> Result<T, revault_net::Error>>(
        &self,
        request: R,
    ) -> Result<T, revault_net::Error> {
        let mut error: Option<revault_net::Error> = None;
        for _ in 0..self.retries {
            match request() {
                Ok(res) => return Ok(res),
                Err(e) => error = Some(e),
            }
            log::debug!(
                "Error while communicating with coordinator: {}, retrying",
                error.as_ref().expect("An error must have happened"),
            );
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
        Err(error.expect("An error must have happened"))
    }

    fn send_req<T>(&self, req: &revault_net::message::Request) -> Result<T, revault_net::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        log::debug!(
            "Sending request to Coordinator: '{}'",
            serde_json::to_string(req).unwrap(),
        );
        let mut transport =
            KKTransport::connect(self.host, &self.our_noise_secret_key, &self.pub_key)?;
        transport.send_req(&req)
    }

    // Get Spend transaction spending the vault with the given deposit outpoint.
    pub fn get_spend_transaction(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Transaction>, revault_net::Error> {
        let resp: SpendTx = self.retry(|| {
            let msg = GetSpendTx { deposit_outpoint };
            self.send_req(&msg.into())
        })?;
        log::debug!(
            "Got from Coordinator: '{}'",
            serde_json::to_string(&resp).unwrap()
        );
        Ok(resp.spend_tx)
    }
}
