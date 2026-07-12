//! The MCP server surface: five note tools exposed over rmcp's Streamable HTTP
//! transport. Every tool is a thin wrapper over `Notes`; the Bearer middleware
//! (see `oauth::bearer`) gates the transport, so a tool is only reachable with a
//! valid owner token.

use std::sync::Arc;

use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{
    ErrorData, ServerHandler, handler::server::wrapper::Parameters, tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::config::Config;
use crate::notes::Notes;

const DEFAULT_SEARCH_LIMIT: usize = 50;

#[derive(Clone)]
pub struct FsGate {
    notes: Arc<Notes>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchArgs {
    /// Case-insensitive text to search for across all notes.
    query: String,
    /// Maximum number of matching lines to return (default 50).
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadArgs {
    /// Path to the note, relative to the served root.
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListArgs {
    /// Optional path prefix to list under, relative to the served root.
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateArgs {
    /// Path for the new note, relative to the served root. Fails if it exists.
    path: String,
    /// Full contents of the new note.
    content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchArgs {
    /// Path to the note to modify, relative to the served root.
    path: String,
    /// Exact text to replace. Must appear exactly once in the file.
    old_str: String,
    /// Replacement text.
    new_str: String,
}

#[tool_router]
impl FsGate {
    pub fn new(notes: Arc<Notes>) -> Self {
        Self { notes }
    }

    #[tool(
        description = "Full-text search across all notes. Returns matching lines with path and line number."
    )]
    async fn search_notes(
        &self,
        Parameters(args): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = args.limit.unwrap_or(DEFAULT_SEARCH_LIMIT).clamp(1, 500);
        let hits = self
            .notes
            .search(&args.query, limit)
            .map_err(to_tool_error)?;
        let json = serde_json::to_string_pretty(&hits)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }

    #[tool(description = "Read a note and return its full contents (frontmatter + body).")]
    async fn read_note(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let body = self.notes.read(&args.path).map_err(to_tool_error)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(body)]))
    }

    #[tool(
        description = "List note file paths under an optional prefix, relative to the served root."
    )]
    async fn list_notes(
        &self,
        Parameters(args): Parameters<ListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let paths = self
            .notes
            .list(args.prefix.as_deref())
            .map_err(to_tool_error)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            paths.join("\n"),
        )]))
    }

    #[tool(description = "Create a new note. Fails if a file already exists at the path.")]
    async fn create_note(
        &self,
        Parameters(args): Parameters<CreateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.notes
            .create(&args.path, &args.content)
            .map_err(to_tool_error)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "created {}",
            args.path
        ))]))
    }

    #[tool(
        description = "Replace exactly one occurrence of old_str with new_str in a note. Fails safely if the file changes concurrently."
    )]
    async fn patch_note(
        &self,
        Parameters(args): Parameters<PatchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.notes
            .patch(&args.path, &args.old_str, &args.new_str)
            .map_err(to_tool_error)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "patched {}",
            args.path
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for FsGate {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "fsgate exposes a private notes directory. Use search_notes/list_notes to \
                 discover files, read_note to read, create_note to add, and patch_note for \
                 targeted edits. There is no delete or full-overwrite tool by design.",
        )
    }
}

/// Maps a filesystem error to a tool-level error the caller can see. Tool errors
/// are the caller's concern (bad path, missing file), so they are surfaced as
/// `invalid_params` rather than a transport failure.
fn to_tool_error(err: anyhow::Error) -> ErrorData {
    ErrorData::invalid_params(err.to_string(), None)
}

/// Builds the Streamable HTTP tower service. `allowed_hosts` is set from the
/// public origin so requests arriving through the tunnel pass DNS-rebinding
/// validation (the rmcp default only permits loopback hosts).
pub fn service(
    notes: Arc<Notes>,
    config: &Config,
) -> StreamableHttpService<FsGate, LocalSessionManager> {
    let mut allowed_hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(host) = config.public_origin.host_str() {
        allowed_hosts.push(host.to_string());
        if let Some(port) = config.public_origin.port() {
            allowed_hosts.push(format!("{host}:{port}"));
        }
    }

    // `StreamableHttpServerConfig` is non-exhaustive, so start from Default and
    // override via the builder method rather than a struct literal.
    let http_config = StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts);

    StreamableHttpService::new(
        move || Ok(FsGate::new(notes.clone())),
        Arc::new(LocalSessionManager::default()),
        http_config,
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::auth::random_token;

    fn temp_gate() -> (FsGate, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fsgate-mcp-test-{}", random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        let notes = Arc::new(Notes::new(&dir).unwrap());
        (FsGate::new(notes), dir)
    }

    /// Pulls the first text block out of a tool result via its serde shape, which
    /// is stable regardless of the internal `ContentBlock` representation.
    fn text_of(result: &CallToolResult) -> String {
        let value = serde_json::to_value(result).expect("serialize CallToolResult");
        value["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[tokio::test]
    async fn tools_cover_create_read_list_search_and_patch() {
        let (gate, dir) = temp_gate();

        gate.create_note(Parameters(CreateArgs {
            path: "a.md".to_string(),
            content: "alpha keyword".to_string(),
        }))
        .await
        .expect("create succeeds");
        // Creating over an existing file is an error.
        assert!(
            gate.create_note(Parameters(CreateArgs {
                path: "a.md".to_string(),
                content: "again".to_string(),
            }))
            .await
            .is_err()
        );

        let read = gate
            .read_note(Parameters(ReadArgs {
                path: "a.md".to_string(),
            }))
            .await
            .expect("read succeeds");
        assert_eq!(text_of(&read), "alpha keyword");
        // Reading a missing file surfaces a tool error.
        assert!(
            gate.read_note(Parameters(ReadArgs {
                path: "missing.md".to_string(),
            }))
            .await
            .is_err()
        );

        let list = gate
            .list_notes(Parameters(ListArgs { prefix: None }))
            .await
            .expect("list succeeds");
        assert!(text_of(&list).contains("a.md"));

        // limit 0 is clamped up to 1; the keyword still matches.
        let search = gate
            .search_notes(Parameters(SearchArgs {
                query: "KEYWORD".to_string(),
                limit: Some(0),
            }))
            .await
            .expect("search succeeds");
        assert!(text_of(&search).contains("a.md"));
        // A blank query is rejected.
        assert!(
            gate.search_notes(Parameters(SearchArgs {
                query: "   ".to_string(),
                limit: None,
            }))
            .await
            .is_err()
        );

        gate.patch_note(Parameters(PatchArgs {
            path: "a.md".to_string(),
            old_str: "alpha".to_string(),
            new_str: "beta".to_string(),
        }))
        .await
        .expect("patch succeeds");
        let reread = gate
            .read_note(Parameters(ReadArgs {
                path: "a.md".to_string(),
            }))
            .await
            .unwrap();
        assert_eq!(text_of(&reread), "beta keyword");
        // A patch whose old_str is absent fails safely.
        assert!(
            gate.patch_note(Parameters(PatchArgs {
                path: "a.md".to_string(),
                old_str: "absent".to_string(),
                new_str: "x".to_string(),
            }))
            .await
            .is_err()
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn get_info_advertises_tools_and_instructions() {
        let (gate, dir) = temp_gate();
        let info = gate.get_info();
        assert!(info.capabilities.tools.is_some());
        assert!(
            info.instructions
                .as_deref()
                .unwrap_or_default()
                .contains("fsgate")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn to_tool_error_carries_the_cause_message() {
        let err = to_tool_error(anyhow::anyhow!("some path problem"));
        assert!(format!("{err:?}").contains("some path problem"));
    }

    #[test]
    fn service_allows_the_public_origin_host_and_port() {
        use std::net::{IpAddr, Ipv4Addr};

        use url::Url;

        use crate::config::Config;

        let dir = std::env::temp_dir().join(format!("fsgate-mcp-svc-{}", random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = Config {
            root: dir.clone(),
            // A host *and* port exercises both allowed-hosts push branches.
            public_origin: Url::parse("https://fsgate.example:8443").unwrap(),
            state_dir: dir.clone(),
            oauth_password: None,
            allow_password_auth: true,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            mcp_path: "/".to_string(),
            token_signing_key: None,
        };
        let notes = Arc::new(Notes::new(&dir).unwrap());
        // Building the service assembles the allowed-hosts list; just ensure it
        // constructs without panicking.
        let _service = service(notes, &config);
        let _ = std::fs::remove_dir_all(dir);
    }
}
