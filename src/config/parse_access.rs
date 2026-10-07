//! `allow` / `deny` (ngx_http_access_module), `satisfy`, and the
//! `limit_except` block (ngx_http_core_module).

use super::ast::{AccessAddr, AccessConf, AccessRule, LIMIT_EXCEPT_METHODS, LimitExcept, Satisfy};
use super::error::Error;
use super::error::Terminator;
use super::lexer::Lexer;
use super::parse_location::{parse_auth_basic_args, parse_auth_basic_user_file_args};

/// `allow`, `deny` or `satisfy` into `conf`; `false` when `args` is none
/// of them. The caller has checked the `;` terminator.
pub(crate) fn parse_access_directive(
    conf: &mut AccessConf,
    args: &[String],
    lx: &mut Lexer,
) -> Result<bool, Error> {
    match args[0].as_str() {
        "allow" | "deny" => conf.rules.push(parse_access_rule(args, lx)?),
        "satisfy" => {
            if conf.satisfy.is_some() {
                return Err(Error::Duplicate("satisfy"));
            }
            conf.satisfy = Some(match args.get(1).map(String::as_str) {
                Some("all") if args.len() == 2 => Satisfy::All,
                Some("any") if args.len() == 2 => Satisfy::Any,
                _ => {
                    return Err(Error::BadValue {
                        what: "satisfy",
                        got: args[1..].join(" "),
                    });
                }
            });
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// `ngx_http_access_rule`: `all`, `unix:`, an address or a CIDR block.
/// Host bits set in a CIDR block are cleared with a warning, as in nginx.
fn parse_access_rule(args: &[String], lx: &mut Lexer) -> Result<AccessRule, Error> {
    let what = if args[0] == "deny" { "deny" } else { "allow" };
    let [_, value] = args else {
        return Err(Error::BadValue {
            what,
            got: args[1..].join(" "),
        });
    };
    let addr = match value.as_str() {
        "all" => AccessAddr::All,
        "unix:" => AccessAddr::Unix,
        _ => {
            let (addr, low_bits) = parse_cidr(value).ok_or_else(|| Error::BadValue {
                what,
                got: value.clone(),
            })?;
            if low_bits {
                lx.warn(format!("low address bits of {value} are meaningless"));
            }
            addr
        }
    };
    Ok(AccessRule {
        deny: what == "deny",
        addr,
    })
}

/// `ngx_ptocidr`: `addr[/bits]`, IPv4 or IPv6. The flag is set when the
/// address had bits outside the mask (cleared in the result).
fn parse_cidr(text: &str) -> Option<(AccessAddr, bool)> {
    let (addr, bits) = match text.split_once('/') {
        Some((addr, bits)) => (addr, Some(parse_decimal(bits)?)),
        None => (text, None),
    };
    if let Some(addr) = parse_inet_addr(addr) {
        let mask = match bits {
            None => u32::MAX,
            Some(0) => 0,
            Some(bits @ 1..=32) => u32::MAX << (32 - bits),
            Some(_) => return None,
        };
        let v4 = AccessAddr::V4 {
            addr: addr & mask,
            mask,
        };
        return Some((v4, addr & !mask != 0));
    }
    let addr = u128::from(addr.parse::<std::net::Ipv6Addr>().ok()?);
    let mask = match bits {
        None => u128::MAX,
        Some(0) => 0,
        Some(bits @ 1..=128) => u128::MAX << (128 - bits),
        Some(_) => return None,
    };
    let v6 = AccessAddr::V6 {
        addr: addr & mask,
        mask,
    };
    Some((v6, addr & !mask != 0))
}

/// `ngx_inet_addr`: four dot-separated decimal octets. Empty octets count
/// as 0 and leading zeros are decimal, as in nginx.
fn parse_inet_addr(text: &str) -> Option<u32> {
    let mut addr: u32 = 0;
    let mut octet: u32 = 0;
    let mut dots = 0;
    for b in text.bytes() {
        match b {
            b'0'..=b'9' => {
                octet = octet * 10 + u32::from(b - b'0');
                if octet > 255 {
                    return None;
                }
            }
            b'.' => {
                addr = (addr << 8) | octet;
                octet = 0;
                dots += 1;
            }
            _ => return None,
        }
    }
    (dots == 3).then_some((addr << 8) | octet)
}

/// `ngx_atoi` for a prefix length: digits only, at least one.
fn parse_decimal(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `limit_except METHOD ... { ... }`: the method list, then a block of
/// access directives (`ngx_http_core_limit_except`). nginx also allows
/// `proxy_pass` and `access_log` in the block; here they are unknown,
/// so such a config fails to load rather than lose them.
pub(crate) fn parse_limit_except_block(
    args: &[String],
    lx: &mut Lexer,
) -> Result<LimitExcept, Error> {
    if args.len() < 2 {
        return Err(Error::MissingArg("limit_except"));
    }
    let mut methods = 0u16;
    for name in &args[1..] {
        let i = LIMIT_EXCEPT_METHODS
            .iter()
            .position(|m| m.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::BadValue {
                what: "limit_except method",
                got: name.clone(),
            })?;
        methods |= 1 << i;
    }
    // GET implies HEAD.
    methods |= (methods & 1) << 1;
    let mut access = AccessConf::default();
    let mut auth_basic = None;
    let mut auth_basic_user_file = None;
    loop {
        let (args, term) = lx.read_directive()?;
        let Some(name) = args.first() else {
            return match term {
                Terminator::BlockClose => Ok(LimitExcept {
                    methods,
                    rules: access.rules,
                    auth_basic,
                    auth_basic_user_file,
                }),
                Terminator::Eof => Err(Error::UnclosedBlock),
                _ => Err(Error::UnexpectedEof),
            };
        };
        match (name.as_str(), term) {
            ("allow" | "deny", Terminator::Semi) => {
                parse_access_directive(&mut access, &args, lx)?;
            }
            ("auth_basic", Terminator::Semi) => {
                if auth_basic.is_some() {
                    return Err(Error::Duplicate("auth_basic"));
                }
                auth_basic = Some(parse_auth_basic_args(&args[1..])?);
            }
            ("auth_basic_user_file", Terminator::Semi) => {
                if auth_basic_user_file.is_some() {
                    return Err(Error::Duplicate("auth_basic_user_file"));
                }
                auth_basic_user_file = Some(parse_auth_basic_user_file_args(
                    &args[1..],
                    lx.conf_prefix(),
                )?);
            }
            ("allow" | "deny" | "auth_basic" | "auth_basic_user_file", _) => {
                return Err(Error::WrongTerminator {
                    name: name.clone(),
                    ctx: "limit_except",
                });
            }
            _ => {
                return Err(Error::UnknownDirective {
                    name: name.clone(),
                    ctx: "limit_except",
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(text: &str) -> Result<(AccessAddr, bool), ()> {
        parse_cidr(text).ok_or(())
    }

    #[test]
    fn cidr_parses_ipv4_and_ipv6() {
        assert_eq!(
            rule("10.1.2.3"),
            Ok((
                AccessAddr::V4 {
                    addr: 0x0a01_0203,
                    mask: u32::MAX
                },
                false
            ))
        );
        assert_eq!(
            rule("10.0.0.0/8"),
            Ok((
                AccessAddr::V4 {
                    addr: 0x0a00_0000,
                    mask: 0xff00_0000
                },
                false
            ))
        );
        assert_eq!(
            rule("0.0.0.0/0"),
            Ok((AccessAddr::V4 { addr: 0, mask: 0 }, false))
        );
        assert_eq!(
            rule("::1"),
            Ok((
                AccessAddr::V6 {
                    addr: 1,
                    mask: u128::MAX
                },
                false
            ))
        );
        assert_eq!(
            rule("2001:db8::/32"),
            Ok((
                AccessAddr::V6 {
                    addr: 0x2001_0db8 << 96,
                    mask: u128::MAX << 96
                },
                false
            ))
        );
    }

    #[test]
    fn cidr_clears_low_bits_and_flags_them() {
        assert_eq!(
            rule("127.0.0.1/8"),
            Ok((
                AccessAddr::V4 {
                    addr: 0x7f00_0000,
                    mask: 0xff00_0000
                },
                true
            ))
        );
        assert_eq!(
            rule("2001:db8::1/64"),
            Ok((
                AccessAddr::V6 {
                    addr: 0x2001_0db8 << 96,
                    mask: u128::MAX << 64
                },
                true
            ))
        );
    }

    #[test]
    fn cidr_follows_ngx_inet_addr_quirks() {
        // Leading zeros are decimal, empty octets are 0.
        assert_eq!(
            rule("010.0.0.1"),
            Ok((
                AccessAddr::V4 {
                    addr: 0x0a00_0001,
                    mask: u32::MAX
                },
                false
            ))
        );
        assert_eq!(
            rule("1..2.3"),
            Ok((
                AccessAddr::V4 {
                    addr: 0x0100_0203,
                    mask: u32::MAX
                },
                false
            ))
        );
    }

    #[test]
    fn cidr_rejects_bad_values() {
        for bad in [
            "",
            "256.0.0.1",
            "1.2.3",
            "1.2.3.4.5",
            "1.2.3.4/33",
            "1.2.3.4/",
            "1.2.3.4/-1",
            "1.2.3.4/x",
            "::1/129",
            "localhost",
            "1.2.3.4 ",
        ] {
            assert_eq!(rule(bad), Err(()), "{bad:?}");
        }
    }
}
