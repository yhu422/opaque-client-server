use std::net::TcpStream;
use std::io::Write;
use rand::rngs::OsRng;
use rand::{Rng, RngCore, thread_rng};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CipherSuite, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload
};

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

fn register(
    mut stream: TcpStream,
    user_id: usize,
    password: String,
    secret_message: String,
) {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();
    let registration_request_bytes = client_registration_start_result.message.serialize();
    stream.write_all(&[0]);
    stream.write_all(&registration_request_bytes);
    stream.flush();
}
fn main() {
    if let Ok(mut stream) = TcpStream::connect("127.0.0.1:7878") {
        println!("Connected to the server!");
        register(stream, 1, "123456".to_string(), "hello world".to_string());
    } else {
        println!("Couldn't connect to server...");
    }
}