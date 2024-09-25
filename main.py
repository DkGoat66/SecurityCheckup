from flask import Flask, request, render_template
import dns.resolver

app = Flask(__name__)


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


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_domain():
    domain = request.form['domain']
    selector = request.form['selector']

    # Get the SPF record and analyze its security
    spf_record = get_spf(domain)
    spf_analysis = analyze_spf_security(spf_record)

    # Get the Dkim record
    dkim_record = get_dkim(domain, selector)

    return render_template('result.html', domain=domain, spf=spf_record, spf_analysis=spf_analysis, dkim=dkim_record)


if __name__ == '__main__':
    app.run(debug=True)
