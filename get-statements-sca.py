import os
import sys
import base64
import json
import rsa
import urllib3
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone

private_key_path = '/Users/michal/.ssh/wise_rsa.pem'  # Change to private key path
profile_id = '25984956'                     # Change to profile ID
balance_id = '26471881'                     # Change to borderless account ID
base_url = 'https://api.transferwise.com'

if os.getenv('API_TOKEN') is None:
    print('panic: no api token, please set with $ export API_TOKEN=xxx')
    sys.exit(0)
elif profile_id == '' or balance_id == '':
    print('panic: profile / account ID missing, please add them')
    sys.exit(0)
elif os.path.exists(private_key_path) is False:
    print('panic: private key file not found, please update key path')
    sys.exit(0)

token = os.getenv('API_TOKEN')  # Set API token from env
http = urllib3.PoolManager()
format = 'xml'
interval_start = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
interval_end = datetime.now(timezone.utc).isoformat()

def get_statement(one_time_token, signature):

    params = urlencode({
        'currency': 'EUR', 'type': 'FLAT',
        'intervalStart': interval_start,
        'intervalEnd': interval_end})

    url = (
        base_url + '/v1/profiles/' + profile_id + '/balance-statements/' 
        + balance_id + '/statement.'+format+'?' + params)

    headers = {
        'Authorization': 'Bearer ' + token,
        'User-Agent': 'tw-statements-sca',
        # 'Content-Type': 'application/'
        }
    if one_time_token != "":
        headers['x-2fa-approval'] = one_time_token
        headers['X-Signature'] = signature
        print(headers['x-2fa-approval'], headers['X-Signature'])

    print('GET', url)
    print('HEADERS', headers)

    r = http.request('GET', url, headers=headers, retries=False)

    print('status:', r.status)
    
    if r.status == 200 or r.status == 201:
        return r
    elif r.status == 403 and r.headers.get('x-2fa-approval') is not None:
        one_time_token = r.headers.get('x-2fa-approval')
        signature = do_sca_challenge(one_time_token)
        response = get_statement(one_time_token, signature)
        return response
    else:
        print('failed: ', r.status)
        print(r.data)
        sys.exit(0)

def do_sca_challenge(one_time_token):
    print('doing sca challenge')

    # Read the private key file as bytes.
    with open(private_key_path, 'rb') as f:
        private_key_data = f.read()

    private_key = rsa.PrivateKey.load_pkcs1(private_key_data, 'PEM')

    # Use the private key to sign the one-time-token that was returned 
    # in the x-2fa-approval header of the HTTP 403.
    signed_token = rsa.sign(
        one_time_token.encode('ascii'), 
        private_key, 
        'SHA-256')

    # Encode the signed message as friendly base64 format for HTTP 
    # headers.
    signature = base64.b64encode(signed_token).decode('ascii')

    return signature

def main():
    r = get_statement("", "")
    content_type = r.headers.get('Content-Type')

    print(r.headers.get('Content-Type'))

    # if content_type is 'application/json' and r.data is not None and 'currency' in r.data['request']:
    #     currency = r.data['request']['currency']
    # elif content_type in ['application/pdf']:
    #     with open('wise.pdf', 'wb') as f:
    #         f.write(r.data)
    # else:
    #     print('something is wrong')
    #     print(r.data)
    #     sys.exit(0)
    with open('wise-statement-'+interval_start[:10]+'-'+interval_end[:10]+'.'+ format, 'wb') as f:
        f.write(r.data)   
    # if 'transactions' in r.data:
    #     txns = len(r.data['transactions'])
    # else:
    #     print('Empty statement')
    #     sys.exit(0)

    # print('\n', currency, 'statement received with', txns, 'transactions.')

if __name__ == '__main__':
    main()