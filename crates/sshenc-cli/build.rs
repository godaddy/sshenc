fn main() {
    #[cfg(target_os = "windows")]
    {
        winresource::WindowsResource::new()
            .compile()
            .expect("Failed to compile Windows resource");
    }
}
