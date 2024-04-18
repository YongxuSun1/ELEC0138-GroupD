# Smart Company Posting System

## Overview
The Smart Company Posting System is an academic project developed to emulate a secure communication platform for corporate use. This Flask-based application allows registered users and administrators to post messages and comments within a controlled environment.

## Features
- **User Authentication**: Login and registration system for users and administrators.
- **Post & Comment**: Users can post messages and leave comments on existing posts.
- **Admin Privileges**: Admins have the ability to delete posts and review all users' credentials.
- **Security Measures**: Implementation of CAPTCHA for brute force attack mitigation, IP-based session authentication, and client-side field encryption to protect against MITM attacks.
- 
## Branches
- **main**: This branch contains the original version of the application, serving as a baseline for development and initial testing.
- **encrypted_version**: The security-enhanced version of the application, featuring additional protections such as client-side field encryption to secure data transmission.

## Installation
Before running the `main.py`, ensure you have the following packages installed:

- Flask
- pymongo
- PyCryptodome
- Pillow
To set up the project, follow these steps:
1. Clone the desired branch of the repository:
   For the original version:
  ```bash
  git clone -b main https://github.com/YongxuSun1/ELEC0138-GroupD.git
  ```
  For the security-enhanced version:
  ```bash
  git clone -b encrypted_version https://github.com/YongxuSun1/ELEC0138-GroupD.git
  ```

2. Run the Flask application:
```bash
python main.py
```
  After starting the application, you can navigate to http://my-public-ip:5000 on your web browser to access the system.

Security and Privacy
The project adheres to the GDPR principles and employs MongoDB for data storage, renowned for its robust encryption and strict access control. Note that this system is built solely for academic purposes and is authorized for testing within an educational scope, not for commercial use.

## Contributors
- **Yongxu Sun**: Developed the initial platform.
- **Ling-Tung Lee**: Implemented security against brute force attacks.
- **Mingyu Jia**: Managed session hijacking protection.
- **Zheng Qin**: Applied client field encryption to safeguard data transmission.

## Disclaimer
The attack strategies discussed and implemented in this project are meant for vulnerability evaluations within a controlled setting. Unauthorized use of these methods on external systems is prohibited and against the code of ethics in cybersecurity.
