from flask import Flask, redirect, request
import hmac

app = Flask(__name__)

CLIENT_ID = 'yourclientidhere'
CLIENT_SECRET = 'yourclientsecrethere'
API_URL = 'https://altdentifier.com'


def verify_signature(req):
    token = req.headers.get('Digest').split("=", 1)[1]
    new_digest = hmac.new(key=CLIENT_SECRET.encode(), msg=req.data).hexdigest()
    return hmac.compare_digest(token, new_digest)


@app.route('/invite')
def invite_me():
    return redirect(f'%s/oauth2/authorize?client_id=%s&scope=write:integrations' % (API_URL, CLIENT_ID))


@app.route('/webhook', methods=['POST'])
def webhook():
    if not verify_signature(request):
        return 'Signature could not verified', 403
    payload = request.json
    event = payload['OP']
    member_name = payload['member']['name']
    guild_name = payload['guild']['name']
    if event == 0:
        print('Verification started for %s in %s ' % (member_name, guild_name))
    elif event == 1:
        print('Verification passed by %s in %s ' % (member_name, guild_name))
    elif event == 2:
        print('Verification failed for %s in %s ' % (member_name, guild_name))
    elif event == 3:
        print('Verification ignored by %s in %s ' % (member_name, guild_name))
    elif event == 4:
        print('Account incorrect for %s in %s ' % (member_name, guild_name))
    elif event == 5:
        print('Test event')
    return '', 204


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=7000)
