use std::{
    io::{prelude::*, Write, Read},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    collections::HashMap
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
fn bytes_to_u32(length_vector: &[u8]) -> u32 {
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

fn handle_connection(server_setup: &ServerSetup<DefaultCipherSuite>,
                     mut stream: TcpStream,
                     mut registered_lockers: &Arc<Mutex<HashMap<String, Locker>>>
    ){
    let mut type_buffer: [u8; 1] = [0];
    let mut length_buffer: [u8; 4] = [0,0,0,0];
    let mut rng = OsRng;
    loop {
    stream.read_exact(&mut type_buffer);
    if type_buffer[0] == 0 {
        stream.read_exact(&mut length_buffer);
        let mut length: usize = 0;

        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        //println!("{}", length);
        let mut registration_request_buffer = vec![0;length];
        stream.read_exact(&mut registration_request_buffer);
        stream.read_exact(&mut length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        let mut username_buffer = vec![0;length];
        stream.read_exact(&mut username_buffer);
        //println!("Registration Request Bytes: {:?}", registration_request_buffer);
        //println!("Username Bytes: {:?}", username_buffer);
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            server_setup,
            RegistrationRequest::deserialize(&registration_request_buffer).unwrap(),
            &username_buffer
        ).unwrap();

        //Prepare sending registration response
        let registration_response_bytes = server_registration_start_result.message.serialize();
        //println!("Registration Response Bytes: {:?}", registration_response_bytes);
        length = registration_response_bytes.len();
        //println!("Registration Response Length: {}", length);
        let mut length_vector : Vec<u8> = Vec::with_capacity(4);
        for i in (0..4).rev() {
            // Extract individual bytes using bitwise operations
            let byte = ((length >> (i * 8)) & 0xFF) as u8;
            length_vector.push(byte);
        }
        //println!("Registration Response Length Bytes: {:?}", length_vector);
        length_vector.extend(registration_response_bytes);
        stream.write_all(&length_vector); 
        stream.flush();
        // In a real setting, a signature over the registration response bytes and a Challenge will also be sent. Omitted for simplicity

        stream.read_exact(&mut length_buffer);
        //println!("Length Buffer: {:?}", length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        //println!("Ciphertext Buffer Length: {}", length);
        let mut ciphertext_buffer = vec![0;length];
        stream.read_exact(&mut ciphertext_buffer);
        //println!("CipherText: {:?}", ciphertext_buffer);
        stream.read_exact(&mut length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        //println!("Registration Result Buffer Length: {}", length);
        let mut registration_result_buffer = vec![0;length];
        stream.read_exact(&mut registration_result_buffer);
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
        println!("Registration Complete")
    }else if type_buffer[0] == 1{
        stream.read_exact(&mut length_buffer);
        let mut length: usize = 0;

        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        //println!("{}", length);
        let mut credential_request_buffer = vec![0;length];
        stream.read_exact(&mut credential_request_buffer);
        stream.read_exact(&mut length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        let mut username_buffer = vec![0;length];
        stream.read_exact(&mut username_buffer);
        println!("Login Request Bytes: {:?}", credential_request_buffer);
        println!("Username Bytes: {:?}", username_buffer);        
        let mut m = registered_lockers.lock().unwrap();
        let locker = m.get(&String::from_utf8(username_buffer.clone()).unwrap()).unwrap();
        let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(&locker.password_file).unwrap();
        println!("{:?}", &locker.password_file);
        let server_login_start_result = ServerLogin::start(
            &mut rng,
            server_setup,
            Some(password_file),
            CredentialRequest::deserialize(&credential_request_buffer).unwrap(),
            &username_buffer,
            ServerLoginStartParameters::default(),
        )
        .unwrap();
        let credential_response_bytes = server_login_start_result.message.serialize();
        println!("Credential Response Bytes: {:?}", credential_response_bytes);
        length = credential_response_bytes.len();
        println!("Credential Response Length: {}", length);
        let mut length_vector : Vec<u8> = Vec::with_capacity(4);
        for i in (0..4).rev() {
            // Extract individual bytes using bitwise operations
            let byte = ((length >> (i * 8)) & 0xFF) as u8;
            length_vector.push(byte);
        }
        println!("Credential Response Length Bytes: {:?}", length_vector);
        length_vector.extend(credential_response_bytes);
        stream.write_all(&length_vector); 
        stream.flush();

        //Read Credential Finalization
        stream.read_exact(&mut length_buffer);
        println!("Length Buffer: {:?}", length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        let mut credential_finalization_buffer = vec![0;length];
        stream.read_exact(&mut credential_finalization_buffer);
        let server_login_finish_result = server_login_start_result
        .state
        .finish(CredentialFinalization::deserialize(&credential_finalization_buffer).unwrap())
        .unwrap();
        let encrypted_locker_contents =
        encrypt(&server_login_finish_result.session_key, &locker.contents);
        println!("Encrypted Locker Contents: {:?}", encrypted_locker_contents);
        let mut length_vector2 : Vec<u8> = Vec::with_capacity(4);
        length = encrypted_locker_contents.len();
        for i in (0..4).rev() {
            // Extract individual bytes using bitwise operations
            let byte = ((length >> (i * 8)) & 0xFF) as u8;
            length_vector2.push(byte);
        }
        length_vector2.extend(encrypted_locker_contents);
        stream.write_all(&length_vector2);
    }else {
        break;
    }
    }
}


fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let registered_lockers = Arc::new(Mutex::new(HashMap::new()));
    let mut rng = OsRng;
    let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
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
