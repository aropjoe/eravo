# Eravo
Eravo is a powerful Django application designed to streamline incident response in the realm of cybersecurity. With a focus on providing real-time insights, it empowers security professionals to swiftly assess the maliciousness of files, URLs, and IP addresses during security incidents. 

It facilitates the creation of incident records, enables the submission of potentially harmful items for analysis, and delivers comprehensive analysis results from diverse security data sources. By offering a centralized platform for incident management and threat evaluation, Eravo enhances the efficiency and effectiveness of incident response workflows, enabling proactive defense against emerging cybersecurity threats.

## Table of Contents
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features

- Display trends in malware detection based on VirusTotal scans.
- Show commonly targeted industries with threat statistics.
- Visualize geographic origins of threats.
- Integrate with VirusTotal API for real-time data retrieval.
- Provide a user-friendly dashboard for easy data exploration.
- Create incident records with descriptions and status.
- Submit files, URLs, or IP addresses for analysis during security incidents.
- Retrieve insights and analysis results from multiple security data sources.
- View incident details, including submitted malicious items and their analysis results.
- Perform quick searches for IOCs such as files, URLs, or IP addresses in VirusTotal's database.
- View search results and insights obtained from VirusTotal's scans.
- Maintain a record of past IOC search queries for historical reference.



## Getting Started

### Prerequisites

- Python (>= 3.6)
- Django (>= 3.0)

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/AropJoe/eravo.git
   cd eravo
   ```

2. Install the project dependencies:

   ```sh
   pip install -r requirements.txt
   ```

### Configuration

1. Obtain a VirusTotal API key by signing up on the [VirusTotal website](https://www.virustotal.com).
2. Create a `.env` file in the project root and add your API key:

   ```ini
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

## Usage

1. Run the Django development server:

   ```sh
   python manage.py runserver
   ```

2. Access the Eravo dashboard by opening your web browser and navigating to `http://127.0.0.1:8000/dashboard/`.

3. Populate scan results by visiting `http://127.0.0.1:8000/populate-scan-results/` and providing the SHA256 hash of the file to fetch data for.

## Contributing

Contributions are welcome! If you'd like to contribute to Eravo, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and write tests if necessary.
4. Test your changes thoroughly.
5. Create a pull request to the main repository's `main` branch.

## License

This project is licensed under the [MIT License](LICENSE).
