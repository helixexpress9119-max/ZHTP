use anyhow::{Result, anyhow};
use std::collections::HashSet;
use regex::Regex;

/// Comprehensive input validation utilities for ZHTP
pub struct InputValidator;

impl InputValidator {
    /// Maximum lengths for various input types
    const MAX_NODE_ID_LENGTH: usize = 64;
    const MAX_CONTENT_LENGTH: usize = 10_000_000; // 10MB
    const MAX_TAG_LENGTH: usize = 100;
    const MAX_TAGS_COUNT: usize = 20;
    const MAX_DOMAIN_LENGTH: usize = 253;
    const MAX_CONTENT_TYPE_LENGTH: usize = 100;
    const MAX_SEARCH_RESULTS: usize = 1000;

    /// Validate node identifier
    pub fn validate_node_id(id: &str) -> Result<()> {
        if id.is_empty() {
            return Err(anyhow!("Node ID cannot be empty"));
        }
        
        if id.len() > Self::MAX_NODE_ID_LENGTH {
            return Err(anyhow!("Node ID too long (max {} characters)", Self::MAX_NODE_ID_LENGTH));
        }
        
        // Only allow alphanumeric, hyphens, and underscores
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!("Node ID contains invalid characters (only alphanumeric, -, _ allowed)"));
        }
        
        // Prevent common attack patterns
        if id.contains("..") || id.starts_with('-') || id.ends_with('-') {
            return Err(anyhow!("Node ID contains invalid patterns"));
        }
        
        Ok(())
    }

    /// Validate and sanitize content input
    pub fn validate_content(content: &[u8]) -> Result<()> {
        if content.is_empty() {
            return Err(anyhow!("Content cannot be empty"));
        }
        
        if content.len() > Self::MAX_CONTENT_LENGTH {
            return Err(anyhow!("Content too large (max {} bytes)", Self::MAX_CONTENT_LENGTH));
        }
        
        // Check for null bytes and other problematic characters
        if content.contains(&0) {
            return Err(anyhow!("Content contains null bytes"));
        }
        
        Ok(())
    }

    /// Validate content type
    pub fn validate_content_type(content_type: &str) -> Result<()> {
        if content_type.is_empty() {
            return Err(anyhow!("Content type cannot be empty"));
        }
        
        if content_type.len() > Self::MAX_CONTENT_TYPE_LENGTH {
            return Err(anyhow!("Content type too long"));
        }
        
        // Basic MIME type validation
        let mime_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9][a-zA-Z0-9\!\#\$\&\-\^\_]*\/[a-zA-Z0-9][a-zA-Z0-9\!\#\$\&\-\^\_\+]*$")
            .map_err(|_| anyhow!("Failed to create MIME type regex"))?;
        
        if !mime_regex.is_match(content_type) {
            return Err(anyhow!("Invalid content type format"));
        }
        
        Ok(())
    }

    /// Validate tags
    pub fn validate_tags(tags: &Option<Vec<String>>) -> Result<()> {
        if let Some(tag_list) = tags {
            if tag_list.len() > Self::MAX_TAGS_COUNT {
                return Err(anyhow!("Too many tags (max {})", Self::MAX_TAGS_COUNT));
            }
            
            let mut seen_tags = HashSet::new();
            
            for tag in tag_list {
                if tag.is_empty() {
                    return Err(anyhow!("Tag cannot be empty"));
                }
                
                if tag.len() > Self::MAX_TAG_LENGTH {
                    return Err(anyhow!("Tag too long (max {} characters)", Self::MAX_TAG_LENGTH));
                }
                
                // Only allow safe characters in tags
                if !tag.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ' ') {
                    return Err(anyhow!("Tag '{}' contains invalid characters", tag));
                }
                
                // Prevent duplicate tags
                if !seen_tags.insert(tag.to_lowercase()) {
                    return Err(anyhow!("Duplicate tag: {}", tag));
                }
            }
        }
        
        Ok(())
    }

    /// Validate domain name
    pub fn validate_domain(domain: &str) -> Result<()> {
        if domain.is_empty() {
            return Err(anyhow!("Domain cannot be empty"));
        }
        
        if domain.len() > Self::MAX_DOMAIN_LENGTH {
            return Err(anyhow!("Domain too long (max {} characters)", Self::MAX_DOMAIN_LENGTH));
        }
        
        // Basic domain validation regex
        let domain_regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.)*[a-zA-Z]{2,}$")
            .map_err(|_| anyhow!("Failed to create domain regex"))?;
        
        if !domain_regex.is_match(domain) {
            return Err(anyhow!("Invalid domain format"));
        }
        
        // Prevent common attacks
        if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
            return Err(anyhow!("Domain contains invalid patterns"));
        }
        
        Ok(())
    }

    /// Validate numeric input with range
    pub fn validate_numeric_input(input: &str, min: u64, max: u64) -> Result<u64> {
        let value = input.trim().parse::<u64>()
            .map_err(|_| anyhow!("Invalid numeric input: {}", input))?;
        
        if value < min || value > max {
            return Err(anyhow!("Value {} out of range ({}-{})", value, min, max));
        }
        
        Ok(value)
    }

    /// Sanitize user input by removing dangerous characters
    pub fn sanitize_input(input: &str) -> String {
        input
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .take(1000) // Limit length
            .collect()
    }

    /// Validate search query to prevent injection attacks
    pub fn validate_search_query(query: &str) -> Result<()> {
        if query.is_empty() {
            return Err(anyhow!("Search query cannot be empty"));
        }
        
        if query.len() > 200 {
            return Err(anyhow!("Search query too long"));
        }
        
        // Check for SQL injection patterns (case-insensitive)
        let sql_patterns = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "UNION", "EXEC", "EXECUTE"
        ];
        
        // Check for XSS and other dangerous patterns (case-sensitive)
        let xss_patterns = [
            "<script", "</script", "javascript:", "vbscript:", "onload=",
            "onerror=", "onclick=", "onmouseover=", "onfocus=", "onblur="
        ];
        
        // Check for path traversal and other patterns
        let other_patterns = [
            "--", "/*", "*/", ";", "../", "..\\", "\0"
        ];
        
        let query_upper = query.to_uppercase();
        let query_lower = query.to_lowercase();
        
        // Check SQL patterns (case-insensitive)
        for pattern in &sql_patterns {
            if query_upper.contains(pattern) {
                return Err(anyhow!("Search query contains dangerous SQL pattern: {}", pattern));
            }
        }
        
        // Check XSS patterns (case-insensitive for tags)
        for pattern in &xss_patterns {
            if query_lower.contains(&pattern.to_lowercase()) {
                return Err(anyhow!("Search query contains dangerous XSS pattern: {}", pattern));
            }
        }
        
        // Check other dangerous patterns
        for pattern in &other_patterns {
            if query.contains(pattern) {
                return Err(anyhow!("Search query contains dangerous pattern: {}", pattern));
            }
        }
        
        // Check for quotes that could be used for injection
        if query.contains('\'') || query.contains('"') || query.contains('`') {
            return Err(anyhow!("Search query contains dangerous quote characters"));
        }
        
        Ok(())
    }

    /// Validate storage capacity
    pub fn validate_storage_capacity(capacity: u64) -> Result<()> {
        const MIN_CAPACITY: u64 = 1_000; // 1KB minimum
        const MAX_CAPACITY: u64 = 1_000_000_000_000; // 1TB maximum
        
        if capacity < MIN_CAPACITY {
            return Err(anyhow!("Storage capacity too small (min {} bytes)", MIN_CAPACITY));
        }
        
        if capacity > MAX_CAPACITY {
            return Err(anyhow!("Storage capacity too large (max {} bytes)", MAX_CAPACITY));
        }
        
        Ok(())
    }

    /// Validate socket address string
    pub fn validate_socket_addr(addr_str: &str) -> Result<()> {
        addr_str.parse::<std::net::SocketAddr>()
            .map_err(|_| anyhow!("Invalid socket address format: {}", addr_str))?;
        Ok(())
    }
}

/// Input validation for CLI interface
pub struct CliValidator;

impl CliValidator {
    /// Read and validate user choice from a menu
    pub fn read_menu_choice(prompt: &str, max_choice: u32) -> Result<u32> {
        print!("{}", prompt);
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        let choice = InputValidator::validate_numeric_input(input.trim(), 1, max_choice as u64)? as u32;
        Ok(choice)
    }

    /// Read and validate text input
    pub fn read_text_input(prompt: &str, max_length: usize, allow_empty: bool) -> Result<String> {
        print!("{}", prompt);
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if !allow_empty && input.is_empty() {
            return Err(anyhow!("Input cannot be empty"));
        }
        
        if input.len() > max_length {
            return Err(anyhow!("Input too long (max {} characters)", max_length));
        }
        
        Ok(InputValidator::sanitize_input(input))
    }

    /// Read and validate tags input
    pub fn read_tags_input(prompt: &str) -> Result<Option<Vec<String>>> {
        let input = Self::read_text_input(prompt, 500, true)?;
        
        if input.is_empty() {
            return Ok(None);
        }
        
        let tags: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        
        InputValidator::validate_tags(&Some(tags.clone()))?;
        Ok(Some(tags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_validation() {
        // Valid node IDs
        assert!(InputValidator::validate_node_id("node1").is_ok());
        assert!(InputValidator::validate_node_id("my-node_123").is_ok());
        
        // Invalid node IDs
        assert!(InputValidator::validate_node_id("").is_err()); // Empty
        assert!(InputValidator::validate_node_id("node with spaces").is_err()); // Spaces
        assert!(InputValidator::validate_node_id("node/with/slashes").is_err()); // Slashes
        assert!(InputValidator::validate_node_id("../malicious").is_err()); // Path traversal
        assert!(InputValidator::validate_node_id(&"x".repeat(100)).is_err()); // Too long
    }

    #[test]
    fn test_content_validation() {
        // Valid content
        assert!(InputValidator::validate_content(b"Hello, world!").is_ok());
        
        // Invalid content
        assert!(InputValidator::validate_content(b"").is_err()); // Empty
        assert!(InputValidator::validate_content(b"content\0with\0nulls").is_err()); // Null bytes
        assert!(InputValidator::validate_content(&vec![65; 20_000_000]).is_err()); // Too large
    }

    #[test]
    fn test_search_query_validation() {
        // Valid queries
        assert!(InputValidator::validate_search_query("simple search").is_ok());
        assert!(InputValidator::validate_search_query("tag:example").is_ok());
        
        // Invalid queries
        assert!(InputValidator::validate_search_query("SELECT * FROM").is_err()); // SQL injection
        assert!(InputValidator::validate_search_query("<script>alert()</script>").is_err()); // XSS
        assert!(InputValidator::validate_search_query("../../../etc/passwd").is_err()); // Path traversal
    }

    #[test]
    fn test_domain_validation() {
        // Valid domains
        assert!(InputValidator::validate_domain("example.com").is_ok());
        assert!(InputValidator::validate_domain("sub.example.com").is_ok());
        
        // Invalid domains
        assert!(InputValidator::validate_domain("").is_err()); // Empty
        assert!(InputValidator::validate_domain(".example.com").is_err()); // Leading dot
        assert!(InputValidator::validate_domain("example..com").is_err()); // Double dots
        assert!(InputValidator::validate_domain("invalid_domain").is_err()); // No TLD
    }
}
