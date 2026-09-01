use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub database_max_connections: u32,
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub upload_dir: String,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_from: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub google_redirect_url: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub github_redirect_url: Option<String>,
}

impl AppConfig {
    pub fn load_from_env() -> Result<Self, String> {
        let server_host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .map_err(|e| format!("Invalid SERVER_PORT: {e}"))?;

        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL environment variable is strictly required".to_string())?;

        let database_max_connections = env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "20".to_string())
            .parse::<u32>()
            .map_err(|e| format!("Invalid DATABASE_MAX_CONNECTIONS: {e}"))?;

        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| "JWT_SECRET environment variable is strictly required".to_string())?;

        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters long for security".to_string());
        }

        let jwt_expiration_hours = env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse::<i64>()
            .map_err(|e| format!("Invalid JWT_EXPIRATION_HOURS: {e}"))?;

        let upload_dir = env::var("UPLOAD_DIR").unwrap_or_else(|_| "uploads".to_string());

        let smtp_host = env::var("SMTP_HOST").ok();
        let smtp_port = env::var("SMTP_PORT").ok().and_then(|p| p.parse().ok());
        let smtp_from = env::var("SMTP_FROM").ok();

        let google_client_id = env::var("GOOGLE_CLIENT_ID").ok();
        let google_client_secret = env::var("GOOGLE_CLIENT_SECRET").ok();
        let google_redirect_url = env::var("GOOGLE_REDIRECT_URL").ok();

        let github_client_id = env::var("GITHUB_CLIENT_ID").ok();
        let github_client_secret = env::var("GITHUB_CLIENT_SECRET").ok();
        let github_redirect_url = env::var("GITHUB_REDIRECT_URL").ok();

        Ok(Self {
            server_host,
            server_port,
            database_url,
            database_max_connections,
            jwt_secret,
            jwt_expiration_hours,
            upload_dir,
            smtp_host,
            smtp_port,
            smtp_from,
            google_client_id,
            google_client_secret,
            google_redirect_url,
            github_client_id,
            github_client_secret,
            github_redirect_url,
        })
    }
}
