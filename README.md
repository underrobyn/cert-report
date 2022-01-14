# Certificate Report

Generates a CSV report for multiple hostnames provided in a txt file.

---

###  Why would you want to use this?

If you have a large amount of servers you need to quickly check SSL information for
(i.e. expiry dates, algorithm used) then this script is for you!

### How to use?

Step 1) Clone this repo
```bash
git clone https://github.com/jake-cryptic/cert-report
cd cert report
```

Step 2) Edit urls.txt (use urls.txt.example to help)

Step 3) Choose a method below to run the script

#### Docker (Recommended)

```bash
docker build -t cert-report .
docker run -v $(pwd):/src/report cert-report
```