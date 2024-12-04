# vrv_security
⭐WEB SERVER LOG ANALYZER⭐
This Python script reads a web server log file to analyze request patterns and detect possible security threats.
It identifies:
The number of requests made by each IP address.
The most commonly used endpoint.
Suspicious activities, like a failed login attempt, based on some configurable threshold.
The results are then printed out in the terminal and also saved to a CSV file for reporting purposes.
⭐Features
Request Analysis: counts the requests made by each individual's IP address.
Endpoint Access Tracking: It identifies the most accessed endpoint.
Failed Login Detection This identifies IP addresses with login failures that exceed the threshold specified (default is 5).
CSV Reporting saves the results from the analysis into a CSV file for further review.
⭐Prerequisites
Python 3.6 or later
Required libraries:
re
csv
collections (defaultdict, Counter)
⭐Usage
Place the log file you want to analyze in the same directory as the script (default: sample.log).
Run the script:
python log_analyzer.py
The script will display results in the terminal and save them into a CSV file named log_analysis_results.csv.
########################################
