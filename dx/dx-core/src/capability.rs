//! Capabilities: the accesses a script may get (files, a database, the network...), which Turbo grants for each
//! request.
//!
//! A capability deals only in [`Value`]: it doesn't know the engine that exposes it, so one written once serves every
//! engine. An engine only converts between `Value` and the types of its language, and exposes what [`Granted`] holds: it
//! doesn't know any capability. A worker is built with the capabilities it can offer ([`Capabilities`]); each request
//! gets only those Turbo named in its pair `DX_GRANTS`, none when it names none. A client can't name them: its headers
//! reach a worker as `HTTP_*` pairs.

use crate::protocol::Request;
use std::cell::RefCell;
use std::fmt;
use std::path::Path;
use std::time::Instant;

/// A value that crosses between a script and a capability: what every language has.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    Num(f64),
    /// A text, or any bytes.
    Bytes(Vec<u8>),
    List(Vec<Value>),
    /// Pairs in the order they were made; a key is not repeated.
    Map(Vec<(Value, Value)>),
}

impl Value {
    pub fn text(text: &str) -> Value {
        Value::Bytes(text.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    pub fn as_int(&self) -> Option<i64> {
        match *self {
            Value::Int(i) => Some(i),
            Value::Num(n) if n.fract() == 0.0 && n >= i64::MIN as f64 && n < i64::MAX as f64 => Some(n as i64),
            _ => None,
        }
    }

    /// The value of a key of a map.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs.iter().find(|(k, _)| k.as_bytes() == Some(key.as_bytes())).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Why a call to a capability failed: the engine raises it as an error of the script.
#[derive(Clone, Debug, PartialEq)]
pub enum CapError {
    /// The capability, or the function, isn't granted to this request (or doesn't exist).
    Denied(String),
    /// The arguments aren't what the function takes.
    Arguments(String),
    /// The time of the request is over.
    Timeout,
    /// Anything else.
    Failed(String),
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CapError::Denied(what) => write!(f, "{what} isn't granted"),
            CapError::Arguments(why) => write!(f, "wrong arguments: {why}"),
            CapError::Timeout => f.write_str("the time of the request is over"),
            CapError::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for CapError {}

/// What a call knows of the request that makes it: what a capability needs to limit itself to it.
pub struct Call<'a> {
    request: &'a Request,
}

impl<'a> Call<'a> {
    pub fn request(&self) -> &'a Request {
        self.request
    }

    /// The folder of the site (`DOCUMENT_ROOT`): a capability with files keeps to it.
    pub fn document_root(&self) -> Option<&'a Path> {
        let root = std::str::from_utf8(self.request.get("DOCUMENT_ROOT")?).ok()?;
        (!root.is_empty()).then(|| Path::new(root))
    }

    /// When Turbo gives up the request: a capability that waits gives up before.
    pub fn deadline(&self) -> Option<Instant> {
        self.request.deadline()
    }

    /// `CapError::Timeout` if the time of the request is over.
    pub fn check_time(&self) -> Result<(), CapError> {
        match self.deadline() {
            Some(deadline) if Instant::now() >= deadline => Err(CapError::Timeout),
            _ => Ok(()),
        }
    }
}

/// An access that a script may get: "kv", "fs", "http"...
pub trait Capability {
    /// Its name: what Turbo grants, and what a script sees (in Lua, `turbox.<name>.<function>`). Lower-case letters,
    /// digits and `_`, starting with a letter.
    fn name(&self) -> &'static str;

    /// Its functions, by name; a call names one by its index in this list.
    fn functions(&self) -> &'static [&'static str];

    /// Runs a function for a script.
    fn call(&mut self, function: usize, call: &Call, args: &[Value]) -> Result<Value, CapError>;

    /// After each request it was granted to, whatever happened: it drops what is for one request only (a worker may
    /// serve another site next).
    fn end_request(&mut self) {}
}

/// The capabilities a worker can offer, of which Turbo grants some to each request.
#[derive(Default)]
pub struct Capabilities {
    list: Vec<Entry>,
}

/// A capability with its name and functions, read once: finding one never borrows it.
struct Entry {
    name: &'static str,
    functions: &'static [&'static str],
    capability: RefCell<Box<dyn Capability>>,
}

impl Capabilities {
    /// No capability: a script gets nothing but its language.
    pub fn none() -> Capabilities {
        Capabilities::default()
    }

    /// Adds a capability. Panics on a name that isn't valid or that is already there: that is a mistake of whoever
    /// builds the worker, found when it starts.
    pub fn with<C: Capability + 'static>(mut self, capability: C) -> Capabilities {
        let name = capability.name();
        let valid = name.starts_with(|c: char| c.is_ascii_lowercase())
            && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
        assert!(valid, "the name of a capability must be lower-case letters, digits and _: {name:?}");
        assert!(!self.names().contains(&name), "two capabilities named {name:?}");
        let functions = capability.functions();
        self.list.push(Entry { name, functions, capability: RefCell::new(Box::new(capability)) });
        self
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.list.iter().map(|e| e.name).collect()
    }

    /// The capabilities granted to a request: those of its pair `DX_GRANTS` that the worker has.
    pub fn grant<'a>(&'a self, request: &'a Request) -> Granted<'a> {
        let names = request.grants();
        let list = self.list.iter().filter(|e| names.contains(&e.name)).collect();
        Granted { request, list }
    }
}

/// The capabilities granted to one request: the only ones an engine may expose to its script. When it is dropped,
/// each one ends the request.
pub struct Granted<'a> {
    request: &'a Request,
    list: Vec<&'a Entry>,
}

impl<'a> Granted<'a> {
    /// Nothing granted.
    pub fn none(request: &'a Request) -> Granted<'a> {
        Granted { request, list: Vec::new() }
    }

    /// The names of the capabilities granted, with their functions.
    pub fn list(&self) -> Vec<(&'static str, &'static [&'static str])> {
        self.list.iter().map(|e| (e.name, e.functions)).collect()
    }

    /// Calls a function of a granted capability.
    pub fn call(&self, name: &str, function: &str, args: &[Value]) -> Result<Value, CapError> {
        let denied = || CapError::Denied(format!("{name}.{function}"));
        let entry = self.list.iter().find(|e| e.name == name).ok_or_else(denied)?;
        let index = entry.functions.iter().position(|f| *f == function).ok_or_else(denied)?;
        let call = Call { request: self.request };
        call.check_time()?;
        let mut capability = entry
            .capability
            .try_borrow_mut()
            .map_err(|_| CapError::Failed(format!("{name} is called again while it runs")))?;
        capability.call(index, &call, args)
    }
}

impl Drop for Granted<'_> {
    fn drop(&mut self) {
        for entry in &self.list {
            if let Ok(mut capability) = entry.capability.try_borrow_mut() {
                capability.end_request();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    /// A capability for the tests: it counts calls and remembers until the request ends.
    struct Probe {
        calls: Rc<RefCell<Vec<String>>>,
        kept: Option<Value>,
    }

    impl Capability for Probe {
        fn name(&self) -> &'static str {
            "probe"
        }
        fn functions(&self) -> &'static [&'static str] {
            &["echo", "keep", "kept", "root"]
        }
        fn call(&mut self, function: usize, call: &Call, args: &[Value]) -> Result<Value, CapError> {
            self.calls.borrow_mut().push(self.functions()[function].to_string());
            match function {
                0 => Ok(Value::List(args.to_vec())),
                1 => {
                    self.kept = Some(args.first().cloned().ok_or_else(|| CapError::Arguments("a value".into()))?);
                    Ok(Value::Nil)
                }
                2 => Ok(self.kept.clone().unwrap_or(Value::Nil)),
                _ => Ok(call.document_root().map(|r| Value::text(&r.to_string_lossy())).unwrap_or(Value::Nil)),
            }
        }
        fn end_request(&mut self) {
            self.kept = None;
            self.calls.borrow_mut().push("end".into());
        }
    }

    fn request(grants: &str) -> Request {
        let pairs = vec![
            (b"DX_GRANTS".to_vec(), grants.as_bytes().to_vec()),
            (b"DOCUMENT_ROOT".to_vec(), b"/srv/site".to_vec()),
        ];
        Request::new(pairs, Vec::new())
    }

    #[test]
    fn denied_by_default() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let capabilities = Capabilities::none().with(Probe { calls: calls.clone(), kept: None });
        for grants in ["", "other", "probe2", "PROBE", " ,"] {
            let request = request(grants);
            let granted = capabilities.grant(&request);
            assert!(granted.list().is_empty(), "{grants:?}");
            assert_eq!(granted.call("probe", "echo", &[]), Err(CapError::Denied("probe.echo".into())));
        }
        let without = Request::new(Vec::new(), Vec::new());
        assert!(capabilities.grant(&without).list().is_empty());
        assert!(calls.borrow().is_empty(), "nothing ran, nothing ended");
    }

    #[test]
    fn granted_and_ended() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let capabilities = Capabilities::none().with(Probe { calls: calls.clone(), kept: None });
        let request = request("other, probe");
        {
            let granted = capabilities.grant(&request);
            assert_eq!(granted.list(), vec![("probe", &["echo", "keep", "kept", "root"][..])]);
            assert_eq!(granted.call("probe", "echo", &[Value::Int(1)]), Ok(Value::List(vec![Value::Int(1)])));
            assert_eq!(granted.call("probe", "missing", &[]), Err(CapError::Denied("probe.missing".into())));
            assert!(matches!(granted.call("probe", "keep", &[]), Err(CapError::Arguments(_))));
            granted.call("probe", "keep", &[Value::text("x")]).unwrap();
            assert_eq!(granted.call("probe", "kept", &[]), Ok(Value::text("x")));
            assert_eq!(granted.call("probe", "root", &[]), Ok(Value::text("/srv/site")));
        }
        assert_eq!(calls.borrow().last().map(String::as_str), Some("end"));
        let granted = capabilities.grant(&request);
        assert_eq!(granted.call("probe", "kept", &[]), Ok(Value::Nil), "nothing crosses to the next request");
    }

    #[test]
    fn time_over() {
        let capabilities = Capabilities::none().with(Probe { calls: Default::default(), kept: None });
        let pairs = vec![(b"DX_GRANTS".to_vec(), b"probe".to_vec()), (b"DX_TIMEOUT_MS".to_vec(), b"1".to_vec())];
        let request = Request::new(pairs, Vec::new());
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(capabilities.grant(&request).call("probe", "echo", &[]), Err(CapError::Timeout));
    }

    #[test]
    #[should_panic(expected = "two capabilities")]
    fn names_are_not_repeated() {
        let _ = Capabilities::none()
            .with(Probe { calls: Default::default(), kept: None })
            .with(Probe { calls: Default::default(), kept: None });
    }

    #[test]
    fn values() {
        let map = Value::Map(vec![(Value::text("a"), Value::Num(3.0))]);
        assert_eq!(map.get("a").and_then(Value::as_int), Some(3));
        assert_eq!(Value::Num(3.5).as_int(), None);
        assert_eq!(Value::text("é").as_str(), Some("é"));
        assert_eq!(Value::Bytes(vec![0xff]).as_str(), None);
    }
}
