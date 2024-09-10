from flask import Flask, request, render_template
import dns.resolver

app = Flask(__name__)

def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in str(rdata):
                return str(rdata)
    except dns.resolver.NoAnswer:
        return "No SPF record found"
    except Exception as e:
        return f"Error: {str(e)}"

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
