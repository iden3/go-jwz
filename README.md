# jwz
Golang implementation of json web zeroknowledge 

### Usage on older hardware and in GitHub Actions
You might need to switch to Ubuntu-22.04 for GHA and add `rapidsnark_noasm` build tag to your app build command, tests, linters, etc.

```shell
go build -tags rapidsnark_noasm
go test -tags rapidsnark_noasm
```
