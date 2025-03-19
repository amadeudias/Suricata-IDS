# 🛡️ Suricata IDS Home-Lab

## ℹ️ Visão Geral
Este repositório contém a configuração e exercícios práticos para a implementação de um **Home-Lab** com **Suricata IDS**. O objetivo é fornecer experiência prática na implantação e configuração de um **Sistema de Detecção de Intrusão (IDS)** para monitoramento e segurança de rede.  

O **Suricata** é um IDS de código aberto, capaz de detectar e prevenir diversas ameaças baseadas em rede. Este laboratório em casa permite aprender na prática a instalação, configuração e uso do **Suricata** para fortalecer a segurança da rede.

---

## 📌 Conteúdo do Laboratório

🔹 **Requisitos**  
🔹 **Diagrama do Laboratório**  
🔹 **Configuração do Suricata IDS Home-Lab**  
🔹 **Exercícios - Ataques Baseados em Rede**  
🔹 **Exercícios - Ataques Baseados na Web**  

---

## 🧮 Requisitos

### **🔧 Hardware:**
- Computador com pelo menos **16 GB de RAM** e processador **dual-core**  

### **📦 Máquinas Virtuais / Imagens ISO:**
- **Máquina Vítima:** Windows  
- **Máquina Invasora:** Kali Linux  

---

## 🖼️ Diagrama do Laboratório
📌 *(Adicione aqui um diagrama de rede, mostrando as conexões entre as máquinas virtuais e o IDS Suricata.)*  

---

## ⚙️ Configuração do Suricata Home-Lab

### **🖥️ Configurando o Servidor Suricata IDS**
1️⃣ **Importar a OVA** do **Ubuntu Server 22.04** no **VirtualBox**  
2️⃣ **Instalar o Suricata IDS**  

### **🖥️ Configurando os Servidores Vítima**
#### **Servidor Vítima 1 - Aplicação Web Vulnerável**
1️⃣ **Importar a OVA** do **Ubuntu Server 22.04** no **VirtualBox**  
2️⃣ **Instalar DVWA (Damn Vulnerable Web Application)**  

#### **Servidor Vítima 2 - Metasploitable 2**
1️⃣ **Importar a OVA** do **Metasploitable 2**  

#### **Servidor Vítima 3 - Typhoon**
1️⃣ **Importar a OVA** do **Typhoon**  

---

## 🛠️ Exercícios - Ataques Baseados em Rede
### 🔍 **Detecção de Varredura e Reconhecimento**
- **Varredura furtiva do Nmap**  
```yaml
alert tcp any any -> any any (msg:"Nmap Stealth Scan Detected"; flags:S; threshold: type threshold, track by_src, count 5, seconds 10; sid:100001;)
Impressão digital do Nmap OS

yaml
Copiar
Editar
alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 64; content:"ECHO REQUEST"; sid:100002;)
alert icmp any any -> any any (msg:"Nmap OS Fingerprinting Detected"; ttl: 128; content:"ECHO REPLY"; sid:100003;)
Detecção de versão do serviço Nmap

yaml
Copiar
Editar
alert tcp any any -> any any (msg:"Nmap Service Version Detection Probe Detected"; content:"GET"; http_method; sid:100004;)
alert tcp any any -> any any (msg:"Nmap Service Version Detection Probe Detected"; flags:SA; sid:100005;)
🎭 Detecção de Exploração com Metasploit
Carga útil de exploração do Metasploit

yaml
Copiar
Editar
alert tcp any any -> any any (msg:"Metasploit Exploit Payload Detected"; content:"<metasploit_payload>"; sid:100006;)
Shell reverso do Metasploit

yaml
Copiar
Editar
alert tcp any any -> <attacker_ip> any (msg:"Metasploit Reverse Shell Connection Detected"; sid:100007;)
Comunicação do Metasploit Meterpreter

yaml
Copiar
Editar
alert tcp any any -> any any (msg:"Meterpreter Communication Detected"; content:"<meterpreter_payload>"; sid:100008;)
Coleta de credenciais do Metasploit

yaml
Copiar
Editar
alert tcp any any -> any any (msg:"Metasploit Credential Harvesting Activity Detected"; content:"LDAP" content:"SMB"; sid:100009;)
🔥 Exercícios - Ataques Baseados na Web
🌐 Ataques a Aplicações Web
Enumeração de Servidor Web

yaml
Copiar
Editar
alert http any any -> any any (msg:"Web Server Enumeration Attempt Detected"; urilen:>100; threshold: type threshold, track by_src, count 10, seconds 60; sid:100010;)
Varredura de Vulnerabilidades em Aplicações Web

yaml
Copiar
Editar
alert http any any -> any any (msg:"Web Application Vulnerability Scan Detected"; content:"SQL Injection" content:"XSS"; sid:100011;)
Exploração de Aplicação Web com Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit Web Application Exploitation Attempt Detected"; content:"<exploit_payload>"; sid:100012;)
Injeção de Comando no Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit Command Injection Attempt Detected"; content:";"; sid:100013;)
Travessia de Diretório do Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit Directory Traversal Attempt Detected"; content:"../"; sid:100014;)
Ataque XSS do Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit XSS Attack Detected"; content:"<script>"; sid:100015;)
Injeção de SQL do Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit SQL Injection Attempt Detected"; content:"SQL Error"; sid:100016;)
Inclusão de Arquivo do Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit File Inclusion Attempt Detected"; content:"../../"; sid:100017;)
Ataque CSRF do Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit CSRF Attack Detected"; content:"CSRF Token"; sid:100018;)
Desvio de Autenticação do Metasploit

yaml
Copiar
Editar
alert http any any -> any any (msg:"Metasploit Authentication Bypass Attempt Detected"; content:"Ad
