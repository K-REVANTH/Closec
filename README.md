# CLOSEC
Automated scanner, that scans for you finding out the vulnerabilities, secrets in your projects, images and more...

### Setup - Virtual Environment

**Rule 1:** When you are dealing with Python Projects, always use a virtual env.  
So, Let's setup a virtual environment.  
`$> python --version`  
=> Python 3.12.4
`$> python -m venv env` - virtual environment created   
`$> env\Scripts\activate` - virtual environment activated   
`$> env\Scripts\deactivate.bat` - to deactivate virtual environment   

### Usage
Using Source code:  
```
cd CLI
pip install -r requirements.txt
python main.py -h
Ex: (For a Docker Image Scanning) python main.py -i ubuntu:latest
```
Using exe:  
```
closec -h
Ex: (For a Docker Image Scanning) closec -i ubuntu:latest
```

### Targets 
- [x] Container Image  
- [x] SBOM  
- [x] NodeJS Project `New` 
- [x] Python Project `New`
- [ ] AWS `Dev`  
- [ ] Virtual Machine Image `Dev`
- [ ] Filesystem  
- [ ] Rootfs  
- [ ] Code Repository  
- [ ] Kubernetes  

### Scanner
- [x] Vulnerability  
- [x] Secret  
- [ ] Misconfiguration  
- [ ] License  

### Coverage   
- [x] OS  
  - [x] Alpine Linux
  - [x] Debian GNU/Linux
  - [x] Ubuntu
  - [x] Wolfi Linux
  - [x] Chaingaurd
  - [x] Red Hat Enterprise Linux
  - [ ] CentOS
  - [x] AlmaLinux
  - [x] Rocky Linux
  - [ ] Oracle Linux
  - [x] Amazon Linux
  - [x] OpenSUSE Leap
  - [x] SUSE Enterprise Linux
  - [x] Photon OS
  - [x] Clearlinux `New`
  - [x] CirrOS `New`
  - [x] Bitnami by VMware `New` 
  - [ ] CondaOS `Deprecated`
  - [ ] CBL - Mariner - `404`
* Code ran into some errors while scanning for few OS, will be fixed soon.

- [x]  Language  
  - [x] Python - 
  - [x] Node.js - (npm, yarn)
  - [ ] C/C++
  - [ ] Dart
  - [ ] .NET
  - [ ] Elixir
  - [ ] Go
  - [ ] Java
  - [ ] PHP
  - [ ] Ruby
  - [ ] Rust
  - [ ] Swift
  - [ ] Julia

- [ ] IaC 
  - [ ] Azure ARM Template
  - [ ] CloudFormation
  - [ ] Docker
  - [ ] Helm
  - [ ] Kubernetes
  - [ ] Terraform

- [ ] Kubernetes

### Configuration
- [x] Database
  - [x] Optimization

### Release Updates
1. Eliminated the need of docker engine ✅
2. Increased the support OS ✅
3. Targets ✅
4. Code Optimization ✅
5. Terminal Output  ✅
6. Auto update DB ✅
7. Secret Scanning ✅
8. Search query optimization ✅
9. Database Optimization - `Dev`
10. Virtual Machines - `Dev`

### Next Release
1. AWS Integration 
2. Increasing Support for More Languages
3. Private Hoested Docker Repos

### OS - Images Tested - Benchmarks - DockerScout
| **Image ID**                    | **CLOSEC** | **Docker Scout** |
|:--------------------------------:|:----------:|:----------------:|
| `ubuntu:latest`                 |     131    |      130          |
| `alpine:latest`                 |     17     |       17          |
| `debian:latest`                 |     128    |      125          |
| `bitnami/os-shell:latest`       |     171    |       -           |
| `chainguard/wolfi-base:latest`  |     16     |       -           |
| `chainguard/busybox:latest`     |      9     |       -           |
| `oraclelinux:9`                 |            |                  | 
| `centos:latest`                 |            |                  |
| `almalinux:minimal`             |            |                  |
| `rockylinux:9.3-minimal`        |            |                  |
| `amazonlinux:latest`            |            |                  |
| `photon:latest`                 |            |                  |
| `clearlinux:latest`             |            |                  |
| `cirros:latest`                 |            |                  |
| `redhat/ubi8:latest`            |            |                  |
| `opensuse/leap:latest`          |            |                  |

- Stuck at scanning RPM Package Manager  