#[cfg(test)]
mod tests {
    use crate::find_process;

    #[test]
    fn found_process() {
        assert!(!find_process("svchost.exe").unwrap().is_empty())
    }

    #[test]
    fn not_found_process() {
        use crate::Errors;
        assert_eq!(find_process("").err().unwrap(), Errors::ProcessNotFound)
    }
}
