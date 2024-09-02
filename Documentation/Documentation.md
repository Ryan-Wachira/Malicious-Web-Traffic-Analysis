# Scenario Overview
During a routine cybersecurity investigation, analysts observed unusual traffic patterns on a web server. These patterns raised suspicions of a potential attack. The task was to analyze the captured network traffic and identify the nature of the attack, determine the vulnerabilities exploited, and assess the impact on the system.

## Tools Used
Wireshark: A network protocol analyzer used to capture and analyze network traffic.
Linux Ubuntu Environment: The analysis was conducted in a Linux Ubuntu environment within the LETSDEFEND.IO cloud instance lab.
## Steps and Findings
### 1. Identifying the Web Server
The investigation started by identifying the web server's IP address. By filtering the network traffic on port 443 (HTTPS traffic), the IP address 10.1.0.4 was identified as the web server. This step was crucial in focusing the analysis on relevant traffic.

### 2. Finding the Attacker's IP Address
Next, the focus shifted to identifying the attacker. By analyzing the traffic conversations in Wireshark (Statistics > Conversations), the IP address 197.32.212.121 was found to have an unusually high number of packets sent to the web server. This IP address was identified as the attacker.

### 3. Understanding the Attack - XML External Entity (XXE) Vulnerability
The attacker attempted multiple methods to compromise the web server. Initially, they tried a brute force attack on the login page, but after failing, they targeted the registration page. By filtering the communication between the attacker and the web server
(ip.src == 197.32.212.121 || ip.dst == 197.32.212.121 and ip.src == 10.1.0.4 || ip.dst == 10.1.0.4), 
it was evident that the attacker was exploiting an XML External Entity (XXE) vulnerability.

Encoded Payload: The attacker sent the following payload in a POST request to the registration page (/register/register.php):

```
3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0d0a0d0a3c726f6f743e0d0a20203c6e616d653e61686d65643c2f6e616d653e0d0a20203c74656c3e6b646a6b3c2f74656c3e0d0a20203c656d61696c3e267878653b3c2f656d61696c3e
```

This payload is a typical XXE attack, where the attacker tries to exploit the XML parser by including an external entity reference (&xxe;). This reference can be manipulated to access sensitive data or perform other malicious actions.

Decoded Data: Upon decoding the data from hexadecimal, it translated to:

```
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <name>ahmed</name>
  <tel>kdjk</tel>
  <email>&xxe;</email>
</root>
```

This XML data included an external entity reference, suggesting that the attacker was trying to access sensitive data through the server’s XML parser.

### 4. Server Response and Note in the Source Code
The server processed the malicious request and responded with a base64-encoded message. Upon decoding the base64 data, it revealed the following PHP code snippet:

```
<?php
libxml_disable_entity_loader (false);
$xmlfile = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
$info = simplexml_import_dom($dom);
$name = $info->name;
$tel = $info->tel;
$email = $info->email;
$password = $info->password;
//Admin this comment is just to let you know that we updated your credentials with a very secure password. so noone can brute force it.
//Note: submit me as the answer: yougotme
echo "Sorry $email is already registered!";
?>
```

The comment within the source code revealed the note "yougotme," which served as a clue for the attacker. This comment indicated that the server's credentials had been updated with a secure password, providing the attacker with sensitive information.

### 5. Brute Forcing the Admin Credentials
After decoding the server response, the attacker attempted to brute force the admin credentials. Using the username admin, the attacker repeatedly tried different passwords until the correct password Fernando was found. This successful brute force attack allowed the attacker to gain admin access to the server.

### 6. Directory Traversal Exploit
With admin access, the attacker exploited a directory traversal vulnerability to read sensitive server files. The payload used in the GET request was as follows:

```
../../../../../../../../../../../../../../../etc/passwd
```

This payload enabled the attacker to traverse the directory structure and access the /etc/passwd file, which contains user account information on Unix-based systems.

### 7. Identifying the Last User Created
The contents of the /etc/passwd file revealed several user accounts on the server. The last user created was a1l4mFTW, with the following details:

```
a1l4mFTW:x:1001:1001::/home/a1l4mFTW:/bin/bash
```

This entry indicated that a1l4mFTW was the most recent addition to the system.

### 8. Exploiting the Open Redirect Vulnerability
The attacker also discovered an open redirect vulnerability in the application. By manipulating the URL parameters, the attacker was able to redirect users to a malicious site (https://evil.com/). The manipulated URL was as follows:

```
http://letsdefend.eastus.cloudapp.azure.com/dashboard/redirect.php?url=https%3A%2F%2Fevil.com%2F
```

This type of vulnerability could potentially be used for phishing attacks or other malicious activities by redirecting unsuspecting users to a harmful website.

## Conclusion
The analysis of the captured network traffic revealed several critical vulnerabilities in the web application, including an XXE attack, a directory traversal flaw, and an open redirect issue. The attacker successfully exploited these vulnerabilities to gain unauthorized access, extract sensitive information, and manipulate the system. This scenario highlights the importance of secure coding practices, proper input validation, and the need for continuous monitoring of web traffic to detect and mitigate such attacks.
