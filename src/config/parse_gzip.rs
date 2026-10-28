//! The gzip filter's directives (`ngx_http_gzip_filter_module` and the
//! `gzip_*` ones of `ngx_http_core_module`), at http, server and location
//! level. Unset ones inherit from the level above, as nginx's merge does.
//! `gzip_static` and `gzip_buffers` stay on the ignore list.

use super::*;

/// `gzip_proxied` flags (`NGX_HTTP_GZIP_PROXIED_*`).
pub mod proxied {
    pub const OFF: u16 = 0x0002;
    pub const EXPIRED: u16 = 0x0004;
    pub const NO_CACHE: u16 = 0x0008;
    pub const NO_STORE: u16 = 0x0010;
    pub const PRIVATE: u16 = 0x0020;
    pub const NO_LM: u16 = 0x0040;
    pub const NO_ETAG: u16 = 0x0080;
    pub const AUTH: u16 = 0x0100;
    pub const ANY: u16 = 0x0200;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GzipConf {
    /// `gzip on|off`, default off.
    pub enable: Option<bool>,
    /// `gzip_types`: MIME types besides `text/html`; `*` is any.
    pub types: Option<Vec<String>>,
    /// `gzip_min_length`, default 20.
    pub min_length: Option<u64>,
    /// `gzip_comp_level` 1..9, default 1.
    pub comp_level: Option<u32>,
    /// `gzip_vary`, default off.
    pub vary: Option<bool>,
    /// `gzip_http_version 1.0|1.1`, as 10 / 11; default 11.
    pub http_version: Option<u8>,
    /// `gzip_proxied` flags; default off.
    pub proxied: Option<u16>,
    /// `gzip_disable`: User-Agent regexes; `msie6` is nginx's shortcut.
    pub disable: Option<Vec<String>>,
}

impl GzipConf {
    const DIRECTIVES: &'static [&'static str] = &[
        "gzip",
        "gzip_types",
        "gzip_min_length",
        "gzip_comp_level",
        "gzip_vary",
        "gzip_http_version",
        "gzip_proxied",
        "gzip_disable",
    ];

    pub(crate) fn takes(name: &str) -> bool {
        Self::DIRECTIVES.contains(&name)
    }

    /// The level's own value wins; unset ones come from `parent`.
    pub(crate) fn inherit(self, parent: &GzipConf) -> GzipConf {
        GzipConf {
            enable: self.enable.or(parent.enable),
            types: self.types.or_else(|| parent.types.clone()),
            min_length: self.min_length.or(parent.min_length),
            comp_level: self.comp_level.or(parent.comp_level),
            vary: self.vary.or(parent.vary),
            http_version: self.http_version.or(parent.http_version),
            proxied: self.proxied.or(parent.proxied),
            disable: self.disable.or_else(|| parent.disable.clone()),
        }
    }

    pub(crate) fn parse(&mut self, args: &[String]) -> Result<(), Error> {
        let name = args[0].as_str();
        let values = &args[1..];
        let one = |what: &'static str| -> Result<&String, Error> {
            match values {
                [v] => Ok(v),
                [] => Err(Error::MissingArg(what)),
                _ => Err(Error::BadValue {
                    what,
                    got: values.join(" "),
                }),
            }
        };
        match name {
            "gzip" => {
                dup(&self.enable, "gzip")?;
                self.enable = Some(parse_on_off_args(values, "gzip")?);
            }
            "gzip_vary" => {
                dup(&self.vary, "gzip_vary")?;
                self.vary = Some(parse_on_off_args(values, "gzip_vary")?);
            }
            "gzip_types" => {
                dup(&self.types, "gzip_types")?;
                if values.is_empty() {
                    return Err(Error::MissingArg("gzip_types"));
                }
                self.types = Some(values.iter().map(|t| t.to_ascii_lowercase()).collect());
            }
            "gzip_min_length" => {
                dup(&self.min_length, "gzip_min_length")?;
                let v = one("gzip_min_length")?;
                self.min_length = Some(parse_size(v.as_bytes()).ok_or(Error::BadValue {
                    what: "gzip_min_length",
                    got: v.clone(),
                })?);
            }
            "gzip_comp_level" => {
                dup(&self.comp_level, "gzip_comp_level")?;
                let v = one("gzip_comp_level")?;
                self.comp_level = Some(
                    v.parse::<u32>()
                        .ok()
                        .filter(|n| (1..=9).contains(n))
                        .ok_or(Error::BadValue {
                            what: "gzip_comp_level (must be between 1 and 9)",
                            got: v.clone(),
                        })?,
                );
            }
            "gzip_http_version" => {
                dup(&self.http_version, "gzip_http_version")?;
                let v = one("gzip_http_version")?;
                self.http_version = Some(match v.as_str() {
                    "1.0" => 10,
                    "1.1" => 11,
                    _ => {
                        return Err(Error::BadValue {
                            what: "gzip_http_version",
                            got: v.clone(),
                        });
                    }
                });
            }
            "gzip_proxied" => {
                dup(&self.proxied, "gzip_proxied")?;
                if values.is_empty() {
                    return Err(Error::MissingArg("gzip_proxied"));
                }
                let mut mask = 0;
                for v in values {
                    mask |= match v.as_str() {
                        "off" => proxied::OFF,
                        "expired" => proxied::EXPIRED,
                        "no-cache" => proxied::NO_CACHE,
                        "no-store" => proxied::NO_STORE,
                        "private" => proxied::PRIVATE,
                        "no_last_modified" => proxied::NO_LM,
                        "no_etag" => proxied::NO_ETAG,
                        "auth" => proxied::AUTH,
                        "any" => proxied::ANY,
                        _ => {
                            return Err(Error::BadValue {
                                what: "gzip_proxied",
                                got: v.clone(),
                            });
                        }
                    };
                }
                self.proxied = Some(mask);
            }
            "gzip_disable" => {
                if values.is_empty() {
                    return Err(Error::MissingArg("gzip_disable"));
                }
                for v in values {
                    // `degradation` needs nginx's degradation module, which
                    // ruxen (like most nginx builds) doesn't have.
                    if v != "msie6" && v != "degradation" {
                        crate::pcre::regex(v, true).map_err(|e| Error::InvalidRegex {
                            pattern: v.clone(),
                            msg: e.to_string(),
                        })?;
                    }
                }
                // Several lines add up, as in nginx.
                self.disable
                    .get_or_insert_with(Vec::new)
                    .extend(values.iter().cloned());
            }
            other => unreachable!("not a gzip directive: {other}"),
        }
        Ok(())
    }
}

fn dup<T>(slot: &Option<T>, what: &'static str) -> Result<(), Error> {
    if slot.is_some() {
        Err(Error::Duplicate(what))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(lines: &[&str]) -> Result<GzipConf, Error> {
        let mut g = GzipConf::default();
        for l in lines {
            let args: Vec<String> = l.split_whitespace().map(String::from).collect();
            g.parse(&args)?;
        }
        Ok(g)
    }

    #[test]
    fn parses_every_directive() {
        let g = conf(&[
            "gzip on",
            "gzip_types text/css Application/JSON",
            "gzip_min_length 1k",
            "gzip_comp_level 6",
            "gzip_vary on",
            "gzip_http_version 1.0",
            "gzip_proxied expired no-cache auth",
            "gzip_disable msie6",
            "gzip_disable ^curl",
        ])
        .unwrap();
        assert_eq!(g.enable, Some(true));
        assert_eq!(
            g.types,
            Some(vec!["text/css".to_string(), "application/json".to_string()])
        );
        assert_eq!(g.min_length, Some(1024));
        assert_eq!(g.comp_level, Some(6));
        assert_eq!(g.vary, Some(true));
        assert_eq!(g.http_version, Some(10));
        assert_eq!(
            g.proxied,
            Some(proxied::EXPIRED | proxied::NO_CACHE | proxied::AUTH)
        );
        assert_eq!(
            g.disable,
            Some(vec!["msie6".to_string(), "^curl".to_string()])
        );
    }

    #[test]
    fn rejects_bad_values_and_duplicates() {
        assert!(conf(&["gzip maybe"]).is_err());
        assert!(conf(&["gzip_comp_level 10"]).is_err());
        assert!(conf(&["gzip_http_version 2.0"]).is_err());
        assert!(conf(&["gzip_proxied sometimes"]).is_err());
        assert!(conf(&["gzip_disable ("]).is_err());
        assert!(conf(&["gzip on", "gzip off"]).is_err());
    }

    #[test]
    fn unset_values_inherit() {
        let parent = conf(&["gzip on", "gzip_comp_level 5"]).unwrap();
        let child = conf(&["gzip_comp_level 2"]).unwrap().inherit(&parent);
        assert_eq!(child.enable, Some(true));
        assert_eq!(child.comp_level, Some(2));
    }
}
