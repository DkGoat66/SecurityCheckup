#import necessary modules from Flask and DNS resolver library
from flask import Flask, request, render_template
import dns.resolver

# Intialize the Flask app
app = Flask(__name__)
# Function to get SPF record for a domain
def get_spf(domain):
    try:
        # Query the DNS for the domain's TXT records
        answers = dns.resolver.resolve(domain, 'TXT')

        # Loop through the TXT records to find the SPF record
        for rdata in answers:
            for txt_record in rdata.strings:
                spf_record = txt_record.decode('utf-8')
                if spf_record.startswith("v=spf1"):
                    return spf_record
        return "No SPF record found"

    except dns.resolver.NoAnswer:
        return "No SPF record found"
    except dns.resolver.NXDOMAIN:
        return "Domain not found or no DNS answer."
    except dns.resolver.Timeout:
        return "Request timed out."
    except Exception as e:
        return f"Error: {str(e)}"
#Function to analyze SPF records 
def analyze_spf_security(spf_record):
    if "v=spf1" not in spf_record:
        return "No valid SPF record found."

    # Check for strictness in policy directive
    if spf_record.endswith("-all"):
        return "Strong SPF configuration: emails from unauthorized servers will be rejected."
    elif spf_record.endswith("~all"):
        return "Moderate SPF configuration: emails from unauthorized servers will be accepted but marked suspicious."
    elif spf_record.endswith("?all"):
        return "Neutral SPF configuration: emails from unauthorized servers are treated neutrally."
    elif spf_record.endswith("+all"):
        return "Weak SPF configuration: any server can send emails, making the domain vulnerable."
    else:
        return "SPF record found, but its policy is unclear."



#Function to get DKIM record for a domain
def get_dkim(domain, selector):
    try:
        # Construct the DKIM domain based on the selector and domain
        dkim_domain = f"{selector}._domainkey.{domain}"

        # Query the DNS for DKIM TXT records
        answers = dns.resolver.resolve(dkim_domain, 'TXT')

        # Collect DKIM records
        dkim_records = []
        for rdata in answers:
            dkim_records.append(str(rdata))

        # Return all DKIM records or a message if none found
        if dkim_records:
            return dkim_records
        else:
            return "No DKIM record found"

    except dns.resolver.NoAnswer:
        return "No DKIM record found"
    except dns.resolver.NXDOMAIN:
        return "Domain not found."
    except dns.resolver.Timeout:
        return "Request timed out."
    except Exception as e:
        return f"Error: {str(e)}"


#home  page route 
@app.route('/')
def home():
    return render_template('index.html')
#route to handle form submission from the homepage
@app.route('/check', methods=['POST'])
def check_domain():
    # Get the domain name from the form data
    domain = request.form['domain']
    # Get the SPF record for the domain
    spf_record = get_spf(domain)
    # Get the DKIM record for the domain
    dkim_record = get_dkim(domain)
    # Render the result.html template with the domain, SPF, and DKIM records
    return render_template('result.html', domain=domain, spf=spf_record, dkim=dkim_record)
    
if __name__ == '__main__':
    app.run(debug=True)
