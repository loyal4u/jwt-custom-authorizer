import jwt


def authorize(event, context):
    token = event.get('authorizationToken')
    if not token:
        unauthorized('Authentication token is missing')

    try:
        payload = decode_jwt_token(token)
        return auth_response(payload, 'Allow', event.get('methodArn'))
    except jwt.ExpiredSignatureError:
        unauthorized('Authentication token is expired')
    except jwt.InvalidSignatureError:
        unauthorized('Authentication token is invalid')
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError):
        unauthorized('Incorrect claims, please check the audience and issuer')
    except:
        unauthorized('Unable to parse authentication token')


def unauthorized(message):
    print('Unauthorized: %s' % message)
    raise Exception('Unauthorized')


def decode_jwt_token(token):
    return jwt.decode(
        token,
        'client_secret',
        issuer='issuer',
        audience='audience',
        algorithms='HS256')


def auth_response(token, effect, resource):
    return {
        'principalId': token['sub'],
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        },
        'context': {
            'tenant_id': 'TODO',  # We need to get this information for database
            'email': token['email'],
            'name': token['name'],
            'picture': token['picture'],
            'locale': token['locale']
        }
    }
