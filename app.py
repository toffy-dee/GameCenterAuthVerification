import json
import requests
import struct
import base64
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from os import environ
from urllib.parse import unquote_plus

# Maximum passed time in seconds
MAX_TIMESTAMP_AGE = int(environ.get('MAX_TIMESTAMP_AGE', 300))

def verify_gamecenter_signature(publicKeyUrl, signature, salt, timestamp, playerID, bundleID):
	
	# Makes sure timestamp is within range
	current_time = int(time.time() * 1000)  # Current time in milliseconds
	if current_time - int(timestamp) > MAX_TIMESTAMP_AGE * 1000:
		print("Timestamp is too old.")
		return False
	
	# Makes sure the publicKeyURL contains 'apple.com'
	if 'apple.com' not in publicKeyUrl:
		print("publicKeyUrl is not valid.")
		return False

	# Decode the base64-encoded signature and salt
	decoded_sig = base64.b64decode(signature)
	decoded_salt = base64.b64decode(salt)

	# Download and read the .cer file from Apple and extract the public key
	r = requests.get(publicKeyUrl, stream=True)

	local_filename = '/tmp/' + publicKeyUrl.split('/')[-1]  # Save to /tmp directory
    
	# Based on https://gist.github.com/andyzinsser/8044165
	with open(local_filename, 'wb') as f:
		for chunk in r.iter_content(chunk_size=1024):
				if chunk:
					f.write(chunk)
					f.flush()
	
	# Load the certificate and extract the public key
	with open(local_filename, 'rb') as f:
		der = f.read()
	
	cert = x509.load_der_x509_certificate(der, default_backend())
	public_key = cert.public_key()

	# Prepare the payload
	payload = (
		playerID.encode('utf-8') +
		bundleID.encode('utf-8') +
		struct.pack('>Q', int(timestamp)) +
		decoded_salt
	)

	try:
		# Verify the signature using the public key, padding, and SHA256 hash
		# *Took a while to figure out that it's SHA256()
		public_key.verify(
				decoded_sig,
				payload,
				padding=padding.PKCS1v15(),
				algorithm=hashes.SHA256()
		)
		print('Successfully verified certificate with signature')
		return True
	except Exception as err:
		print(f"Verification failed: {err}")
		return False

def lambda_handler(event, context):

	auth_info = event['queryStringParameters']
	print('auth_info:', auth_info)

	try:
		# Extracts parameters from the event object. Expects client to urlencode the parameters
		publicKeyUrl = unquote_plus(auth_info.get('publicKeyUrl'))
		timestamp = unquote_plus(auth_info.get('timestamp'))
		signature = unquote_plus(auth_info.get('signature'))
		salt = unquote_plus(auth_info.get('salt'))
		playerID = unquote_plus(auth_info.get('playerID'))
		bundleID = unquote_plus(auth_info.get('bundleID'))

		if not all([publicKeyUrl, timestamp, signature, salt, playerID, bundleID]):
			return {
				'statusCode': 400,
				'body': json.dumps('Missing one or more required parameters')
			}

		# Verifies the Game Center signature
		is_valid = verify_gamecenter_signature(publicKeyUrl, signature, salt, timestamp, playerID, bundleID)

		return {
			'statusCode': 200,
			'body': json.dumps({'is_valid': is_valid})
		}
	except Exception as e:
		print(f"Error: {str(e)}")
		return {
			'statusCode': 500,
			'body': json.dumps(f'Internal Server Error: {str(e)}')
		}