use serde::Serialize;

use crate::error::BttError;

/// Envelope for all command output.
#[derive(Serialize)]
struct SuccessEnvelope<T: Serialize> {
    ok: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    ok: bool,
    error: &'a BttError,
}

/// Print a success result as JSON to stdout.
pub fn print_success<T: Serialize>(data: &T, pretty: bool) {
    let envelope = SuccessEnvelope { ok: true, data };
    let json = if pretty {
        serde_json::to_string_pretty(&envelope)
    } else {
        serde_json::to_string(&envelope)
    };
    match json {
        Ok(s) => println!("{}", s),
        Err(e) => {
            eprintln!("fatal: failed to serialize output: {}", e);
            std::process::exit(2);
        }
    }
}

/// Print an error result as JSON to stdout, then exit with code 1.
pub fn print_error(err: &BttError, pretty: bool) -> ! {
    let envelope = ErrorEnvelope {
        ok: false,
        error: err,
    };
    let json = if pretty {
        serde_json::to_string_pretty(&envelope)
    } else {
        serde_json::to_string(&envelope)
    };
    match json {
        Ok(s) => {
            println!("{}", s);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("fatal: failed to serialize error output: {}", e);
            std::process::exit(2);
        }
    }
}
