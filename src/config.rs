pub const DEFAULT_CONF: &str = "targets.conf";

#[derive(Default, Clone, Debug)]
pub struct ConfigFile {
    pub targets: Vec<String>,
    pub post_exec: Option<String>,
}

pub fn load_config_file(path: &str) -> Option<ConfigFile> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut targets = Vec::new();
    let mut post_exec = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if let Some(rest) = lower.strip_prefix("exec=").or_else(|| lower.strip_prefix("exec:")) {
            let idx = trimmed.len() - rest.len();
            post_exec = Some(trimmed[idx..].trim().to_string());
        } else if let Some(rest) = lower.strip_prefix("post_exec=").or_else(|| lower.strip_prefix("post_exec:")) {
            let idx = trimmed.len() - rest.len();
            post_exec = Some(trimmed[idx..].trim().to_string());
        } else {
            targets.push(trimmed.to_string());
        }
    }

    Some(ConfigFile { targets, post_exec })
}

pub fn parse_names_csv(s: &str) -> Vec<String> {
    s.split([',', ';', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

