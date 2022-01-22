# pbkdf2
An optimized PBKDF2 implementation is advantageous for a defender
because an attacker will always have a more powerful setup.

This is an experiment in optimizing PBKDF2.

```
goos: darwin
goarch: arm64
pkg: github.com/ericlagergren/pbkdf2
BenchmarkHMACSHA256
BenchmarkHMACSHA256-8      	    4964	    240688 ns/op	1089.14 MB/s
BenchmarkHMACSHA256_Go
BenchmarkHMACSHA256_Go-8   	    2094	    571200 ns/op	 458.94 MB/s
```

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
