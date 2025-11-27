# MSF API Coverage Analysis

This document analyzes our current Rust/Python bridge implementation against the full Metasploit Framework Ruby API to identify gaps and opportunities for enhancement.

## Analysis Date
2025-11-26

## Current Implementation Status

### ✅ Framework Class - Implemented
| Method | Status | Notes |
|--------|--------|-------|
| `version()` | ✅ Implemented | Returns MSF version string |
| `list_modules(type)` | ✅ Implemented | Lists exploits, auxiliary, payloads |
| `create_module(name)` | ✅ Implemented | Creates module instances |
| `sessions()` | ✅ Implemented | Returns SessionManager |
| `datastore()` | ✅ Implemented | Returns global DataStore |

### ❌ Framework Class - Missing But Available in MSF
| Method | Priority | Use Case |
|--------|----------|----------|
| `db` | High | Database access for hosts, services, vulns, creds |
| `search(string)` | High | Search modules by keyword/cve/name |
| `threads()` / `threads?()` | Medium | Thread management for concurrent operations |
| `encoders()` / `nops()` / `post()` / `evasion()` | Low | Direct access to other module types (currently via list_modules) |

---

### ✅ Module Class - Implemented
| Method | Status | Notes |
|--------|--------|-------|
| `name()` | ✅ Implemented | Short module name |
| `fullname()` | ✅ Implemented | Full module path |
| `description()` | ✅ Implemented | Module description |
| `module_type()` | ✅ Implemented | Type (exploit/auxiliary/etc.) |
| `datastore()` | ✅ Implemented | Module-specific options |
| `set_option(k, v)` | ✅ Implemented | Set single option |
| `get_option(k)` | ✅ Implemented | Get single option value |
| `validate()` | ✅ Implemented | Validate required options |
| `exploit(payload, opts)` | ✅ Implemented | Run exploit module |
| `run(opts)` | ✅ Implemented | Run auxiliary module |
| `check()` | ✅ Implemented | Check if target is vulnerable |
| `has_check?()` | ✅ Implemented | Check if module supports checking |
| `compatible_payloads()` | ✅ Implemented | List compatible payloads |

### ❌ Module Class - Missing But Available in MSF
| Method | Priority | Use Case | Ruby Method |
|--------|----------|----------|-------------|
| `author` | High | Get module authors | `module.author` (attr_reader) |
| `author_to_s` | Medium | Comma-separated authors | `module.author_to_s` |
| `options` | High | Get OptionContainer with full metadata | `module.options` (attr_reader) |
| `alias` | Low | Module alias name | `module.alias` |
| `disclosure_date` | Medium | Vulnerability disclosure date | `module.disclosure_date` |
| `notes` | Low | Module notes (AKA, NOCVE descriptors) | `module.notes` |
| `references` | High | CVE, BID, URL references | `module.references` (attr_reader) |
| `platform` | High | Target platforms | `module.platform` (attr_reader) |
| `arch` | High | Target architectures | `module.arch` (attr_reader) |
| `targets` | High | Exploit targets | `module.targets` (for exploits) |
| `rank` | Medium | Exploit reliability ranking | `module.rank` |
| `privileged` | Low | Requires privileges? | `module.privileged` |
| `license` | Low | Module license | `module.license` |

---

### ✅ DataStore Class - Implemented
| Method | Status | Notes |
|--------|--------|-------|
| `get(key)` | ✅ Implemented | Get value (case-insensitive) |
| `set(key, value)` | ✅ Implemented | Set value (case-insensitive) |
| `to_dict()` / `to_h()` | ✅ Implemented | Convert to dict/hash |

### ❌ DataStore Class - Missing But Available in MSF
| Method | Priority | Use Case | Ruby Method |
|--------|----------|----------|-------------|
| `delete(key)` | Low | Remove option | `datastore.delete(key)` |
| `keys` | Low | List all keys | `datastore.keys` |
| `clear` | Low | Clear all values | `datastore.clear` |
| `merge(hash)` | Low | Merge multiple options | `datastore.merge(hash)` |

---

### ✅ SessionManager Class - Implemented
| Method | Status | Notes |
|--------|--------|-------|
| `list()` | ✅ Implemented | List session IDs |
| `get(id)` | ✅ Implemented | Get session by ID |

### ❌ SessionManager Class - Missing But Available in MSF
| Method | Priority | Use Case | Ruby Method |
|--------|----------|----------|-------------|
| `kill(id)` | Medium | Kill session by ID | `framework.sessions.deregister(id)` |
| `count` | Low | Number of sessions | `framework.sessions.length` |
| `each` | Low | Iterate over sessions | `framework.sessions.each` |

---

### ✅ Session Class - Implemented
| Method | Status | Notes |
|--------|--------|-------|
| `info()` | ✅ Implemented | Session info string |
| `alive?()` | ✅ Implemented | Check if alive |
| `execute(cmd)` | ✅ Implemented | Execute command |
| `session_type()` | ✅ Implemented | Session type |
| `kill()` | ✅ Implemented | Kill session |
| `write(data)` | ✅ Implemented | Write data to session |
| `read(len)` | ✅ Implemented | Read data from session |
| `run_cmd(cmd)` | ✅ Implemented | Run meterpreter command |
| `desc()` | ✅ Implemented | Session description |
| `tunnel_peer()` | ✅ Implemented | Tunnel peer info |
| `target_host()` | ✅ Implemented | Target host IP |

### ❌ Session Class - Missing But Available in MSF
| Method | Priority | Use Case | Ruby Method |
|--------|----------|----------|-------------|
| `name` | Low | Session name/label | `session.name` |
| `name=` | Low | Set session name | `session.name = "label"` |
| `session_host` | Medium | Session host IP | `session.session_host` |
| `session_port` | Medium | Session port | `session.session_port` |
| `tunnel_local` | Low | Local tunnel endpoint | `session.tunnel_local` |
| `via_exploit` | Medium | Exploit that created session | `session.via_exploit` |
| `via_payload` | Medium | Payload that created session | `session.via_payload` |
| `dead?()` | Low | Check if dead | `session.dead?` |
| `interactive?()` | Low | Check if interactive | `session.interactive?` |

---

### ✅ PayloadGenerator Class - Implemented
| Method | Status | Notes |
|--------|--------|-------|
| `generate(name, opts)` | ✅ Implemented | Generate raw payload |
| `generate_encoded(name, encoder, iter, opts)` | ✅ Implemented | Generate encoded payload |
| `list_payloads()` | ✅ Implemented | List all payloads |
| `generate_executable(name, plat, arch, opts)` | ✅ Implemented | Generate executable |

### ✅ PayloadGenerator - Complete
No missing methods identified. Implementation is comprehensive.

---

## Missing Major Features

### 1. Database (DB) Interface - HIGH PRIORITY
**Impact:** Major functionality gap

MSF provides extensive database access through `framework.db`:
- Host management (`hosts`, `report_host`)
- Service management (`services`, `report_service`)
- Vulnerability tracking (`vulns`, `report_vuln`)
- Credential storage (`creds`, `report_cred`)
- Loot/data collection (`loot`, `report_loot`)
- Notes and tags

**Recommendation:** Implement `DbManager` class wrapping `framework.db`

```rust
pub struct DbManager {
    ruby_db: Value,
}

impl DbManager {
    pub fn hosts(&self) -> Result<Vec<Host>> { ... }
    pub fn services(&self) -> Result<Vec<Service>> { ... }
    pub fn report_host(&self, opts: HashMap<String, String>) -> Result<i64> { ... }
    // etc.
}
```

---

### 2. Module Search - HIGH PRIORITY
**Impact:** Essential for discovery and usability

MSF provides `framework.search(string)` to find modules by:
- Module name
- CVE/reference numbers
- Platform/architecture
- Description keywords

**Recommendation:** Add search method to Framework

```rust
impl Framework {
    pub fn search(&self, query: &str) -> Result<Vec<SearchResult>> {
        // Call framework.search(query)
        // Parse and return results
    }
}
```

---

### 3. Module Metadata - HIGH PRIORITY
**Impact:** Critical for informed decision-making

Missing crucial module information:
- **`author`** - Know who wrote the module
- **`references`** - CVE, BID, URL references
- **`options`** - Full option metadata (type, required, default, description)
- **`platform`** / **`arch`** - Target requirements
- **`targets`** - Available exploit targets
- **`disclosure_date`** - When vulnerability was disclosed

**Recommendation:** Extend Module class

```rust
impl Module {
    pub fn author(&self) -> Result<Vec<String>> { ... }
    pub fn references(&self) -> Result<Vec<Reference>> { ... }
    pub fn options(&self) -> Result<OptionContainer> { ... }
    pub fn platform(&self) -> Result<Vec<String>> { ... }
    pub fn arch(&self) -> Result<Vec<String>> { ... }
    pub fn targets(&self) -> Result<Vec<Target>> { ... }
    pub fn disclosure_date(&self) -> Result<Option<String>> { ... }
}
```

---

### 4. Jobs/Threading - MEDIUM PRIORITY
**Impact:** Needed for async operations

MSF supports background jobs through `framework.jobs`:
- Run modules in background
- Monitor job status
- Kill/stop jobs

**Recommendation:** Implement `JobManager` class

```rust
pub struct JobManager {
    ruby_jobs: Value,
}

impl JobManager {
    pub fn list(&self) -> Result<Vec<i64>> { ... }
    pub fn get(&self, id: i64) -> Result<Option<Job>> { ... }
    pub fn kill(&self, id: i64) -> Result<bool> { ... }
}
```

---

### 5. Plugins - LOW PRIORITY
**Impact:** Optional extension mechanism

MSF supports plugins through `framework.plugins`. This is less critical for core functionality.

---

## Recommendations Summary

### Immediate Priorities (High Impact)
1. **Module Metadata** - Add `author`, `references`, `options`, `platform`, `arch`, `targets`
2. **Database Interface** - Implement `DbManager` for host/service/vuln tracking
3. **Module Search** - Add `framework.search()`

### Secondary Priorities (Medium Impact)
4. **Jobs/Threading** - Add `JobManager` for background operations
5. **Enhanced Session Info** - Add `session_host`, `session_port`, `via_exploit`, `via_payload`
6. **DataStore Extensions** - Add `delete`, `keys`, `clear`, `merge`

### Low Priority (Nice to Have)
7. **Module Details** - Add `alias`, `notes`, `rank`, `privileged`, `license`
8. **Session Management** - Add `name`, `tunnel_local`, `interactive?`, `dead?`
9. **Plugins** - Add plugin support

---

## Implementation Checklist

### Phase 1: Core Metadata (Estimated: 2-4 hours)
- [ ] Add `Module.author()` - Returns `Vec<String>`
- [ ] Add `Module.references()` - Returns `Vec<Reference>` struct
- [ ] Add `Module.options()` - Returns full OptionContainer
- [ ] Add `Module.platform()` - Returns `Vec<String>`
- [ ] Add `Module.arch()` - Returns `Vec<String>`
- [ ] Add `Module.targets()` - Returns `Vec<Target>` struct (exploits only)
- [ ] Add `Module.disclosure_date()` - Returns `Option<String>`
- [ ] Update Python bridge with new methods

### Phase 2: Database Interface (Estimated: 4-8 hours)
- [ ] Create `DbManager` struct
- [ ] Add `Framework.db()` - Returns `DbManager`
- [ ] Implement `DbManager.hosts()`
- [ ] Implement `DbManager.services()`
- [ ] Implement `DbManager.report_host()`
- [ ] Implement `DbManager.report_service()`
- [ ] Implement `DbManager.report_vuln()`
- [ ] Implement `DbManager.report_cred()`
- [ ] Update Python bridge with DbManager

### Phase 3: Search & Discovery (Estimated: 1-2 hours)
- [ ] Add `Framework.search(query)` - Returns `Vec<SearchResult>`
- [ ] Create `SearchResult` struct
- [ ] Update Python bridge

### Phase 4: Jobs & Threading (Estimated: 3-6 hours)
- [ ] Create `JobManager` struct
- [ ] Add `Framework.jobs()` - Returns `JobManager`
- [ ] Implement `JobManager.list()`
- [ ] Implement `JobManager.get(id)`
- [ ] Implement `JobManager.kill(id)`
- [ ] Create `Job` struct with status/info
- [ ] Update Python bridge

### Phase 5: Session Enhancements (Estimated: 1-2 hours)
- [ ] Add `Session.session_host()`
- [ ] Add `Session.session_port()`
- [ ] Add `Session.via_exploit()`
- [ ] Add `Session.via_payload()`
- [ ] Update Python bridge

---

## Testing Requirements

For each new feature, add integration tests:
1. Test against real MSF installation
2. Verify Ruby method calls work correctly
3. Test error handling for missing/nil values
4. Ensure Python bindings work
5. Update examples

---

## Notes

- All methods should follow existing error handling patterns
- Ruby nil values should be handled gracefully
- Python bindings should use type hints
- Add comprehensive docstrings
- Consider backwards compatibility

---

## Conclusion

**Current Coverage:** ~60% of core MSF functionality
**With Phase 1-3:** ~85% coverage (sufficient for most use cases)
**With All Phases:** ~95% coverage (comprehensive)

The most impactful additions are Module Metadata (Phase 1), Database (Phase 2), and Search (Phase 3). These should be prioritized.
