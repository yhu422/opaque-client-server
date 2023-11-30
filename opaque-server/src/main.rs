use std::{
    io::{prelude::*, Write, Read},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    collections::HashMap,
    time::Instant
};
use rand::rngs::OsRng;
use rand::{Rng, RngCore, thread_rng};
use aes_gcm::{KeyInit, Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use generic_array::GenericArray;
use threadpool::ThreadPool;
use opaque_ke::{ CipherSuite,
    CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationRequestLen, RegistrationResponseLen, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerRegistrationLen, ServerSetup,
};

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

struct Locker {
    guess_count: u8,
    contents: Vec<u8>,
    password_file: GenericArray<u8, ServerRegistrationLen<DefaultCipherSuite>>,
}


//Convert a 4 byte vector to an unsigned int
fn bytes_to_u32(length_vector: &Vec<u8>) -> u32 {
    let mut length: u32 = 0;
    for byte in length_vector {
        length = (length << 8) | *byte as u32;
    }
    length
}

//Convert an unsigned int to a 4 byte vector
fn u32_to_bytes(length: u32) -> Vec<u8> {
    let mut length_vector : Vec<u8> = Vec::with_capacity(4);
    for i in (0..4).rev() {
        // Extract individual bytes using bitwise operations
        let byte = ((length >> (i * 8)) & 0xFF) as u8;
        length_vector.push(byte);
    }
    length_vector
}
//Read the next 4 bytes as length, then constructing a new vector of that length and read that many bytes from stream.
fn read_from_stream(mut stream: &TcpStream) -> Vec<u8> {
    let mut length_buffer: [u8; 4] = [0,0,0,0];
    stream.read_exact(&mut length_buffer).unwrap();
    let length = bytes_to_u32(&mut length_buffer.to_vec());
    let mut byte_vector: Vec<u8> = vec![0;length.try_into().unwrap()];
    stream.read_exact(&mut byte_vector).unwrap();
    byte_vector
}

//Write 4 bytes representing the length of byte_vector to the stream, then write byte_vector to the stream
fn write_to_stream(mut stream: &TcpStream, byte_vector: &Vec<u8>) {
    let length = byte_vector.len();
    let mut length_vector = u32_to_bytes(length.try_into().unwrap());
    length_vector.extend(byte_vector);
    stream.write_all(&length_vector).unwrap();
    stream.flush().unwrap();
}

// Given a key and plaintext, produce an AEAD ciphertext along with a nonce
fn encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key[..32]));

    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    [nonce_bytes.to_vec(), ciphertext].concat()
}

// Decrypt using a key and a ciphertext (nonce included) to recover the original
// plaintext
fn decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key[..32]));
    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..12]),
            ciphertext[12..].as_ref(),
        )
        .unwrap()
}

fn handle_connection(server_setup: &Arc<Mutex<ServerSetup<DefaultCipherSuite>>>,
                     mut stream: TcpStream,
                     registered_lockers: &Arc<Mutex<HashMap<String, Locker>>>
    ){
    let mut type_buffer: [u8; 1] = [0];
    let mut rng = OsRng;
    loop {
    stream.read_exact(&mut type_buffer).unwrap();
    if type_buffer[0] == 0 {
        let start_time = Instant::now();

        let registration_request_buffer = read_from_stream(&stream);
        let username_buffer = read_from_stream(&stream);
        //println!("Registration Request Bytes: {:?}", registration_request_buffer);
        //println!("Username Bytes: {:?}", username_buffer);
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &server_setup.lock().unwrap(),
            RegistrationRequest::deserialize(&registration_request_buffer).unwrap(),
            &username_buffer
        ).unwrap();

        //Prepare sending registration response
        let registration_response_bytes = server_registration_start_result.message.serialize().to_vec();
        write_to_stream(&stream, &registration_response_bytes);
        //println!("Registration Response Bytes: {:?}", registration_response_bytes);
        // In a real setting, a signature over the registration response bytes and a Challenge will also be sent. Omitted for simplicity


        let ciphertext_buffer = read_from_stream(&stream);
        let registration_result_buffer = read_from_stream(&stream);
        //println!("CipherText: {:?}", ciphertext_buffer);
        //println!("Registration Result Buffer: {:?}", registration_result_buffer);
        let password_file = ServerRegistration::finish(
            RegistrationUpload::<DefaultCipherSuite>::deserialize(&registration_result_buffer).unwrap(),
        );
        
        let l = Locker {
            guess_count: 10,
            contents: ciphertext_buffer,
            password_file: password_file.serialize(),
        };
        let mut m = registered_lockers.lock().unwrap();
        m.insert(String::from_utf8(username_buffer).unwrap(), l);

        let end_time = Instant::now();
        let elapsed = end_time.duration_since(start_time);
        println!("Register Takes: {:?}", elapsed);
    }else if type_buffer[0] == 1{
        let start_time = Instant::now();
        //println!("{}", length);
        let credential_request_buffer = read_from_stream(&stream);
        let username_buffer = read_from_stream(&stream);
        //println!("Login Request Bytes: {:?}", credential_request_buffer);
        //println!("Username Bytes: {:?}", username_buffer);        
        let m = registered_lockers.lock().unwrap();
        let locker = m.get(&String::from_utf8(username_buffer.clone()).unwrap()).unwrap();
        let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(&locker.password_file).unwrap();
        //println!("{:?}", &locker.password_file);
        let server_login_start_result = ServerLogin::start(
            &mut rng,
            &server_setup.lock().unwrap(),
            Some(password_file),
            CredentialRequest::deserialize(&credential_request_buffer).unwrap(),
            &username_buffer,
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        //Send CredentialResponse to client
        let credential_response_bytes = server_login_start_result.message.serialize().to_vec();
        write_to_stream(&stream, &credential_response_bytes);
        //println!("Credential Response Bytes: {:?}", credential_response_bytes);

        //Read CredentialFinalization
        let credential_finalization_bytes = read_from_stream(&stream);

        let server_login_finish_result = server_login_start_result
        .state
        .finish(CredentialFinalization::deserialize(&credential_finalization_bytes).unwrap()).unwrap();
        

        //Send content of locker, encrypted with the session key of this login attempt
        let encrypted_locker_contents =
        encrypt(&server_login_finish_result.session_key, &locker.contents);
        write_to_stream(&stream, &encrypted_locker_contents);
        let end_time = Instant::now();
        let elapsed = end_time.duration_since(start_time);
        println!("Login Takes: {:?}", elapsed);
    }else {
        break;
    }
    }
}


fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let registered_lockers = Arc::new(Mutex::new(HashMap::new()));
    let mut rng = OsRng;
    let server_setup = Arc::new(Mutex::new(ServerSetup::<DefaultCipherSuite>::new(&mut rng)));
    let n_workers = 10;
    let pool = ThreadPool::new(n_workers);
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let server_setup_clone = server_setup.clone();
        let registered_lockers_clone = registered_lockers.clone();
        pool.execute(move || {
            handle_connection(&server_setup_clone, stream, &registered_lockers_clone)
        });
    }
}
