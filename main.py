#import necessary modules from Flask and DNS resolver library
from flask import Flask, request, render_template
import dns.resolver

# Intialize the Flask app
app = Flask(__name__)
# Function to get SPF record for a domain
def get_spf(domain):
    try:
        # Resolve the domain for TXT records (SPF records are typically stored in TXT)
        answers = dns.resolver.resolve(domain, 'TXT')
        # Loop through the records and return the SPF record if found
        for rdata in answers:
            if 'v=spf1' in str(rdata):  # SPF records start with 'v=spf1'
                return str(rdata)
    except dns.resolver.NoAnswer:
        # Handle the case when no SPF record is found
        return "No SPF record found"
    except Exception as e:
        # Handle any other exceptions that may occur
        return f"Error: {str(e)}"
#Function to get DKIM record for a domain
def get_dkim(domain):
    try:
        dkim_domain = f"selector._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            return str(rdata)
    except dns.resolver.NoAnswer:
        return "No DKIM record found"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_domain():
    domain = request.form['domain']
    spf_record = get_spf(domain)
    dkim_record = get_dkim(domain)
    return render_template('result.html', domain=domain, spf=spf_record, dkim=dkim_record)

if __name__ == '__main__':
    app.run(debug=True)
