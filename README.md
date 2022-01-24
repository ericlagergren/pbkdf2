# pbkdf2
An optimized PBKDF2 implementation is particularly advantageous 
for a defender because an attacker will always have a more 
powerful setup.

This is an experiment in optimizing PBKDF2.

Every GOOS/GOARCH has the same base optimizations. GOARCH=arm64
has its own assembly core.

TODO: talk about optimizations.

```
=== RUN   Test100ms
    pbkdf2_test.go:120: std:  720311/100ms
    pbkdf2_test.go:121: asm: 1874573/100ms (2.60x)
[...]
BenchmarkHMACSHA256
BenchmarkHMACSHA256-8      	    5451	    219651 ns/op
BenchmarkHMACSHA256_Go
BenchmarkHMACSHA256_Go-8   	      84	  13853241 ns/op
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
