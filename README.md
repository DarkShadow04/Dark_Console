# Dark Console - VirusTotal Analysis Script

## Description

Dark Console is a powerful Python script designed to automate the analysis of URLs and IP addresses using the VirusTotal API. This script categorizes the results into 'Malicious,' 'Phishing,' 'Suspicious,' 'Clean,' and 'Unrated,' and generates comprehensive PDF reports for easy analysis.

## Installation

### Clone the Repository
<pre><code>git clone https://github.com/DarkShadow04/dark-console.git</code></pre>

### Dependencies

#### Python-requirements
<pre><code>sudo apt update</code></pre>
<pre><code>sudo apt install python3-pip</code></pre>
<pre><code>sudo pip install requests</code></pre>
<pre><code>sudo pip install reportlab</code></pre>

#### lolcat-requirement(beautify text)
<pre><code>sudo apt-get install gem</code></pre>
<pre><code>sudo apt install ruby-rubygems</code></pre>
<pre><code>sudo gem install lolcat</code></pre>

## Usage
### Running the Script

<pre><code>python3 dark_console.py -h </code></pre>

<pre><code>python3 dark_console.py [input_type]</code></pre>

### For IP address or URL:

<pre><code>python3 dark_console.py ip</code></pre>
<pre><code>python3 dark_console.py url</code></pre>

###  For analyzing a file containing multiple IPs or URLs:

<pre><code>python3 dark_console.py file</code></pre>

#  Notes
<ul>
  <li>Make sure you have the necessary permissions to install packages.</li>
  <li>Use a virtual environment for safer package management.</li>
  <li>Respect the usage limits and terms of VirusTotal API.</li>
</ul>

<br>
### Author <br>
Dark_Console script by: Dark_Shadow04<br>
GitHub: DarkShadow04<br>
<br>
© 2023 Dark_Shadow04


#  License
This project is licensed under the MIT License.
