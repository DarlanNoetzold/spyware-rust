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
use psutil::process::{Process, ProcessResult};
use std::collections::HashSet;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Iniciou o programa!");
    if let Err(err) = update_aux_data().await {
        eprintln!("Erro ao atualizar dados auxiliares: {:?}", err);
    }

    // Resto do código...

    // Iniciar thread para keylogger
    thread::spawn(move || {
        keylogger();
    });

    // Loop principal
    loop {
        // Resto do código...

        // Aguardar um intervalo
        thread::sleep(Duration::from_secs(1));
    }
}

// ... Resto do código existente ...

fn keylogger() {
    // Resto do código...
}

fn sniffer(tx: std::sync::mpsc::Sender<String>) {
    // Resto do código...
}

fn scanner(tx: std::sync::mpsc::Sender<String>) {
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

fn get_process() -> String {
    let mut info_set = HashSet::new();

    if let Ok(processes) = Process::all() {
        for process in processes {
            if let Ok(info) = process.as_dict() {
                if let Some(name) = info.get("name") {
                    info_set.insert(name.to_string());
                }
            }
        }
    }

    info_set.into_iter().collect::<Vec<String>>().join(",")
}

fn get_image() -> Result<String, Box<dyn std::error::Error>> {
    let image = image::screenshot()?;
    let mut buffer = Vec::new();

    image.write_to(&mut buffer, image::ImageOutputFormat::PNG)?;

    let b64_str = base64::encode(buffer);

    Ok(b64_str)
}

async fn send_alert(log: &str) -> Result<(), Box<dyn std::error::Error>> {
    let headers = do_login().await?;
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", format!("Bearer {}", token).parse()?);
    let has_error: bool;

    let image_result = get_image();
    if image_result.is_err() {
        println!("Error to send Image\n{:?}", image_result.err().unwrap());
        has_error = true;
    }

    let data_alert = if has_error {
        json!({"pcId": gma(), "processos": get_process()})
    } else {
        json!({"pcId": gma(), "imagem": {"id": image_result.unwrap()}, "processos": get_process()})
    };

    let client = reqwest::Client::new();
    match client
        .post("http://localhost:8091/alert/save")
        .headers(headers)
        .json(&data_alert)
        .send()
        .await
    {
        Ok(alert) => {
            println!("{:?}", alert);
            println!("Alert Saved!");
        }
        Err(err) => {
            println!("Error to send Alert\n{:?}", err);
        }
    }

    Ok(())
}

async fn report(log: &str) -> Result<(), Box<dyn std::error::Error>> {
    if is_hate_speech(log).await || is_bad_language(log) || are_malicious_process(log) || verifyng_hate_speech_chatGPT(log).await {
        println!("Foi enviado o report!");
        send_alert(log).await?;
    }
    Ok(())
}
