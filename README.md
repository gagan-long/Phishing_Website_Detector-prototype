# 🛡️ Phishing Website Detector

A powerful, interactive Streamlit app to analyze and detect potential phishing websites using multi-source threat intelligence, content and DOM analysis, and user/community feedback.

---

## 📑 Abstract

Phishing attacks are a persistent threat to digital security. This project presents an open-source, user-friendly tool that analyzes website URLs for phishing risk using technical, content-based, and community-driven approaches. The tool leverages multiple live threat feeds, SSL/WHOIS verification, DOM analysis, and user feedback to provide actionable risk scores and insights.

---

## 🎯 Problem Statement & Objective

**Problem:**  
Phishing websites are increasingly sophisticated, bypassing traditional filters and deceiving users. Existing solutions are often proprietary, lack transparency, or do not leverage community intelligence.

**Objective:**  
To build an open, extensible, and user-friendly phishing website detector that combines technical analysis, threat intelligence, and community reporting to empower users and organizations.

---

## 🚀 Features

- Phishing Risk Scoring
- Multi-Feed Threat Intelligence (PhishTank, OpenPhish, URLhaus)
- Blacklist Checking & Updates
- Directory & File Crawling
- WHOIS & SSL Certificate Checks
- Content & DOM Analysis (login forms, scripts, suspicious keywords)
- Website Screenshot
- VirusTotal Integration (optional)
- User Feedback & Community Reporting
- Phishing Awareness Quiz
- Export Data (blacklist, community votes)
- Modern Streamlit UI

---

## 🛠️ Setup Instructions

1. **Clone the Repository:**
git clone https://github.com/gagan-long/Phishing_Website-Detector.git
cd web_ditector_3.0/tool

2. **Install Dependencies:**
pip install -r requirements.txt

3. **(Optional) Add `.env` for VirusTotal API:**
VT_API_KEY=your_virustotal_api_key

4. **Run the App:**
streamlit run app.py

OR

Go to - https://phishingwebsite-detector-gfbzumnpgev6mwuxdfs25g.streamlit.app/

---

## 💡 Usage

- Enter a URL and click **Analyze**.
- View risk score, technical details, screenshot, and threat intelligence verdicts.
- Submit feedback, report domains, or take the awareness quiz.
- Use **Update Blacklist from Threat Feeds** for latest phishing domains.
- Download blacklist/community reports as needed.

---

## 🎥 Demo Video

[![Watch the Demo](https://img.shields.io/badge/YouTube-Demo%20Video-red?logo=youtube)](https://youtu.be/syWq5gx05mE)

---

## 📸 Screenshots

https://github.com/gagan-long/Phishing_Website-Detector/blob/main/research_paper.pdf

---

## 📄 License

MIT License

---

## 📚 References

1. [PhishTank](https://phishtank.org/)
2. [OpenPhish](https://openphish.com/)
3. [URLhaus](https://urlhaus.abuse.ch/)
4. [VirusTotal](https://www.virustotal.com/)
5. [Streamlit Documentation](https://docs.streamlit.io/)
6. [BeautifulSoup Documentation](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
7. [python-whois](https://pypi.org/project/python-whois/)
8. [Selenium Documentation](https://www.selenium.dev/documentation/)
9. [OWASP Phishing Guide](https://owasp.org/www-community/phishing)
10. [CERT Phishing Resources](https://www.cert.org/)

---

## 🙏 Acknowledgements

- Digisuraksha Parhari Foundation
- Infinisec Technologies Pvt. Ltd.
- All open-source contributors and threat intelligence providers

---

*For full research, code, and presentation, see respective files in this repository.*
