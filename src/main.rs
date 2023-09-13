use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;
use reqwest;
use std::fs::File;
use serde_json::{json, Value}; 
use std::io::Write;


#[tokio::main] // Anote a função main para usarmos o runtime do tokio.
async fn main() {
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

fn sniffer(tx: std::sync::mpsc::Sender<String>) {
    // Resto do código...
}

fn scanner(tx: std::sync::mpsc::Sender<String>) {
    // Resto do código...
}

fn keylogger() {
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
