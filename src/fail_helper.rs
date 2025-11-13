use std::fmt::{Debug, Display};

pub trait FailHelper {
    type T;

    fn crit(self, msg: &str) -> Self::T;
}

impl<S> FailHelper for Option<S> {
    type T = S;

    fn crit(self, msg: &str) -> Self::T {
        match self {
            Some(v) => v,
            None => {
                eprintln!("------FAILURE------\n{}", msg);
                std::process::exit(1);
            }
        }
    }
}

impl<S, E: Debug> FailHelper for Result<S, E> {
    type T = S;

    fn crit(self, msg: &str) -> Self::T {
        match self {
            Ok(v) => v,
            Err(error) => {
                eprintln!("------FAILURE------\n{}\nError: {:?}", msg, error);
                std::process::exit(1);
            }
        }
    }
}

pub fn crit<M: Display>(msg: M) -> ! {
    eprintln!("------FAILURE------\n{}", msg);
    std::process::exit(1);
}
