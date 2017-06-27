#TRUSTED 9513d9257ba3cd19f4e3f05c4809a745bf4d14e0e9ae3c21d68dccc64ab4a60c2d188c965c1d03ef8b99e644ba3e712a37a8cba8263b4304b92e96a1b13d3119b35df783e9e90b46d9fd7004afd211558f3d278e859d8f1edad29819e0daae7ed4ce51d813ca3b73e802b578b4d30b0431f22eee3dfc5e5cbc3633dfe7e978e2ed8191064c02d4f766c7d0b6de542390ab387936ddf0a7cb5b8972edac1561605488e9995df4b661dcf1a649a538785a3c21f9260f9c949a83ab7be98cb3f07832699b6b25a9a440e667af68d47da0d7c4bf5a0ac0c9a0924d83101ab570958cd4ce42e723c5617b038f40cc666cb3115afd267b099a909829642eccc1a880a6c53f27ef798c16c251308ca92890dd1734f9dc40bb4c6025783d7fd320a4c5d98f1963f7f280ec089100e100f7f204fcd457946a3ee1d78f3f937cac50458fd6d523037d77a1e8c10ea277eb51accb5ebe131417743bdada908e4e0d1146b1324a0018aadadc5137940d8e175dad13d1976974dbafcb0ca3c52eb7dcf5f1beaa19885f0680a81e621a357dc1637946f58eef0d52d7d77b18006c999738269d8ace005aa90cf4dc6b688607f4dd259ed457495f88c3da9154ad4e73ff642aef71ec6216491d55cf7f8e5a24940f408d17cf9c914909f4de84b35b4daa03c1d568198a33e9b471bcd37b5665b8c173163f57b798767d23231bbc4ca4d7bf11346f

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.1
#
# @include x509.inc
# @include http.inc
# @include ssl_func.inc
# @include kerberos_func.inc
#

#
# This is an implementation of RFC 2560 "X509 Internet Public Key Infrastructure
# Online Certificate Status Protocol".
#
# @citation: https://www.ietf.org/rfc/rfc2560.txt
#

##
# Extracts the issuer in DER format from the certificate
#
# @param cert - the a certificate in DER format
# @return a byte string or NULL on failure
##
function _get_issuer_der_bytes(cert)
{
	local_var seq = der_parse_sequence(seq:cert, list:TRUE);
	if (isnull(seq) || seq[0] != 3) return NULL;

	seq = der_decode(data:seq[1]);
	if (isnull(seq) || (seq[0] != 0x30)) return NULL;

	local_var pos = 0;
	local_var i = 0;
	while (pos < strlen(seq[1]))
	{
		local_var ret = der_decode(data:seq[1], pos:pos);
		if (isnull(ret)) return NULL;

		if (ret[0] < 0xa0)
		{
			if (i == 2)
			{
				return substr(seq[1], pos, ret[2] - 1);
			}
			i++;
		}
		pos = ret[2];
	}
	return NULL;
}

##
# Extracts the public key in DER format from the certificate
#
# @param cert - the a certificate in DER format
# @return a byte string or NULL on failure
##
function _get_public_key_der_bytes(cert)
{
	local_var seq = der_parse_sequence(seq:cert, list:TRUE);
	if (isnull(seq) || seq[0] != 3) return NULL;

	seq = der_decode(data:seq[1]);
	if (isnull(seq) || (seq[0] != 0x30)) return NULL;

	local_var pos = 0;
	local_var i = 0;
	while (pos < strlen(seq[1]))
	{
		local_var ret = der_decode(data:seq[1], pos:pos);
		if (isnull(ret)) return NULL;

		if (ret[0] < 0xa0)
		{
			if (i == 5)
			{
				local_var pki = ret[1];
				ret = der_decode(data:pki, pos:0);
				if (isnull(ret) || ret[0] != 0x30) return NULL;

				return substr(pki, ret[2] + 5);
			}
			i++;
		}
		pos = ret[2];
	}
	return NULL;
}

###
# Extracts from the server's certificate, the OCSP URI to make the OCSP request to
#
# @param cert a certificate that has been through "parse_der_cert"
# @return a URI string or NULL
###
function get_ocsp_address(cert)
{
	local_var ext = NULL;
	local_var tbs_cert = cert["tbsCertificate"];
	local_var extension = cert_get_ext(id:EXTN_AUTHORITY_INFORMATION_ACCESS, cert:tbs_cert);
	foreach(ext in extension)
	{
		if (ext["accessMethod"] == "1.3.6.1.5.5.7.48.1")
		{
			return ext["accessLocation"]["uniformResourceIdentifier"];
		}
	}
	return NULL;
}

###
# Extracts from the server's certificate, the CA Issuer's URI. This URI should
# point at a certificate. We will use the certificate to generate the OCSP
# request (see: RFC 2560 4.1.1). And possibly to validate the OCSP response.
#
# @param cert a certificate that has been through "parse_der_cert"
# @return a URI string or NULL
###
function get_issuer_cert_address(cert)
{
	local_var ext = NULL;
	local_var tbs_cert = cert["tbsCertificate"];
	local_var extension = cert_get_ext(id:EXTN_AUTHORITY_INFORMATION_ACCESS, cert:tbs_cert);
	foreach(ext in extension)
	{
		if (ext["accessMethod"] == "1.3.6.1.5.5.7.48.2")
		{
			return ext["accessLocation"]["uniformResourceIdentifier"];
		}
	}
	return NULL;
}

###
# This function generates the payload of an OCSP request as described
# in RFC 2560 section 4.1. We use SHA-1 as our hashing algorithm.
#
# @param server_der_cert - the server's certificate in DER format
# @param issuer_der_cert - the issuer's certificate in DER format
# @return an array of bytes representing an ocsp-request - or null.
###
function create_ocsp_request(server_der_cert, issuer_der_cert)
{
	# extract the key bytes
	local_var key_bytes = _get_public_key_der_bytes(cert:issuer_der_cert);
	if (isnull(key_bytes))
	{
		return NULL;
	}

	# extract the issuer bytes
	local_var issuer_bytes = _get_issuer_der_bytes(cert:server_der_cert);
	if (isnull(issuer_bytes))
	{
		return NULL;
	}

	local_var server_cert = parse_der_cert(cert:server_der_cert);

	# oid 1.3.14.3.2.26 (SHA-1)
	local_var ocsp_request = '\x2b\x0e\x03\x02\x1a';
	ocsp_request = der_encode(tag:0x06, data:ocsp_request);
	ocsp_request = der_encode(tag:0x30, data:ocsp_request);
	# octet string
	ocsp_request += der_encode(tag:0x04, data:SHA1(issuer_bytes));
	# octet string
	ocsp_request += der_encode(tag:0x04, data:SHA1(key_bytes));
	# bit string
	ocsp_request += der_encode(tag:0x02, data:server_cert["tbsCertificate"]["serialNumber"]);
	ocsp_request = der_encode(tag:0x30, data:ocsp_request);
	ocsp_request = der_encode(tag:0x30, data:ocsp_request);
	ocsp_request = der_encode(tag:0x30, data:ocsp_request);
	ocsp_request = der_encode(tag:0x30, data:ocsp_request);
	ocsp_request = der_encode(tag:0x30, data:ocsp_request);
	return ocsp_request;
}

##
# Reads the "responseStatus" in the OCSPResponse. This byte indicates
# if the request was processed successfully. See RFC 2560 4.2.1 for possible values.
#
# @param ocsp_response - an OCSPResponse in DER format
# @return TRUE if the status was '0' (good) and FALSE otherwise
##
function response_status_good(ocsp_response)
{
	local_var seq = der_decode(data:ocsp_response);
	if (isnull(seq) || seq[0] != 0x30) return FALSE;
	seq = seq[1];

	local_var resp_status = der_decode(data:seq);
	if (isnull(resp_status) || resp_status[0] != 0x0a || len(resp_status[1]) != 1) return FALSE;
	return resp_status[1] == '\x00';
}

##
# Reads the "responseStatus" in the OCSPResponse. This byte indicates
# if the request was processed successfully. This function returns
# a string with the status as listed in RFC 2560 4.2.1.
#
# @param ocsp_response - an OCSPResponse in DER format
# @return a string representation of the response status
##
function printable_status(ocsp_response)
{
	local_var seq = der_decode(data:ocsp_response);
	if (isnull(seq) || seq[0] != 0x30) return "OCSPResponse is malformed";
	seq = seq[1];

	local_var resp_status = der_decode(data:seq);
	if (resp_status[1] == '\x00') return "Good";
	else if (resp_status[1] == '\x01') return "Malformed Request";
	else if (resp_status[1] == '\x02') return "Internal Error";
	else if (resp_status[1] == '\x03') return "Try Again Later";
	else if (resp_status[1] == '\x05') return "Signature Required";
	else if (resp_status[1] == '\x06') return "Unauthorized";

	return "Unknown Status";
}

##
# Parses the OCSPResponse down to the CertStatus in SingleResponse. See RFC 2560 4.2.1.
#
# @param ocsp_response - an OCSPResponse in DER format
# @param serial_number - the serial number of the certificate we are verifying
# @return NULL on failure. Otherwise a string describing the result (ie 'Not Revoked', 'Revoked', 'Unknown')
##
function get_revocation_status(ocsp_response, serial_number)
{
	if (isnull(serial_number)) return NULL;

	local_var seq = der_decode(data:ocsp_response);
	if (isnull(seq) || seq[0] != 0x30) return NULL;
	seq = seq[1];

	# ResponseStatus - enumerated
	local_var resp_status = der_decode(data:seq);
	if (isnull(resp_status) || resp_status[0] != 0x0a || len(resp_status[1]) != 1) return NULL;

	if (resp_status[1] != '\x00') return NULL;

	# responseBytes[0]
	local_var responseBytes = der_decode(data:seq, pos:resp_status[2]);
	if (isnull(responseBytes) || responseBytes[0] != 0xa0) return NULL;

	# ResponseBytes sequence
	local_var responseBytesSeq = der_decode(data:responseBytes[1]);
	if (isnull(responseBytesSeq) || responseBytesSeq[0] != 0x30) return NULL;

	# verify that this is a basic ocsp response
	local_var responseType = der_decode(data:responseBytesSeq[1]);
	if (isnull(responseType) || responseType[0] != 6) return NULL;
	local_var responseOid = der_decode_oid(oid: responseType[1]);
	if (responseOid != "1.3.6.1.5.5.7.48.1.1") return NULL;

	# response - octet string
	local_var response = der_decode(data:responseBytesSeq[1], pos:responseType[2]);
	if (isnull(response) || response[0] != 4) return NULL;

	# first sequence in BasicOCSPResponse
	local_var response_seq = der_decode(data:response[1]);
	if (isnull(response_seq) || response_seq[0] != 0x30) return NULL;

	# ResponseData sequence
	local_var responseDataSeq = der_decode(data:response_seq[1]);
	if (isnull(responseDataSeq) || responseDataSeq[0] != 0x30) return NULL;

	# ResponseData version 
	local_var version = der_decode(data:responseDataSeq[1]);
	if (!isnull(version) && version[0] == 0xa0)
	{
		# this is not in accordance with the RFC. Yandex Cert Authority, you are on notice!
		version = der_decode(data:responseDataSeq[1], pos:version[2]);
	}
	if (isnull(version) || (version[0] != 0xa2 && version[0] != 0xa1)) return NULL;

	# Get the responder id
	local_var responder_string = der_decode(data:version[1]);
	if (isnull(responder_string) || (responder_string[0] != 0x04 && responder_string[0] != 0x30)) return NULL;

	# Get the produced at time
	local_var produced_at = der_decode(data:responseDataSeq[1], pos:version[2]);
	if (isnull(produced_at) || produced_at[0] != 0x18) return NULL;

	# responses sequence
	local_var responses = der_decode(data:responseDataSeq[1], pos:produced_at[2]);
	if (isnull(responses) || responses[0] != 0x30) return NULL;

	# loop over the single response sequences until we hit the correct serial number
	local_var response_serial = NULL;
	local_var singleResponse = NULL;
	local_var position = 0;

	do
	{
		singleResponse = der_decode(data:responses[1], pos:position);
		if (isnull(singleResponse) || singleResponse[0] != 0x30) return NULL;

		# update position in case we need to loop again
		if (singleResponse[2] <= position) return NULL;
		position = singleResponse[2];

		# cert sequence
		local_var certSequence = der_decode(data:singleResponse[1]);
		if (isnull(certSequence) || certSequence[0] != 0x30) return NULL;

		# hash algorithm
		local_var hashAlgorithm = der_decode(data:certSequence[1]);
		if (isnull(hashAlgorithm) || hashAlgorithm[0] != 0x30) return NULL;

		# issuer name hash
		local_var issuerNameHash = der_decode(data:certSequence[1], pos:hashAlgorithm[2]);
		if (isnull(issuerNameHash)) return NULL;

		# issuer key hash
		local_var issuerKeyHash = der_decode(data:certSequence[1], pos:issuerNameHash[2]);
		if (isnull(issuerKeyHash)) return NULL;

		# serial number
		response_serial = der_decode(data:certSequence[1], pos:issuerKeyHash[2]);
		if (isnull(response_serial)) return NULL;
	}
	while(hexstr(serial_number) != hexstr(response_serial[1]));

	# certStatus
	local_var certStatus = der_decode(data:singleResponse[1], pos:certSequence[2]);
	if (isnull(certStatus)) return NULL;

	if (certStatus[0] == 0x80 || certStatus[0] == 0xa0) return "Not Revoked";
	else if (certStatus[0] == 0xa1) return "Revoked";
	return "Unknown";
}

##
# The OCSPResponse is followed by an RSA signature. This function decrypts
# the signature with the provided certificate's public key and computes the
# hash over OCSPResponse to validate the decrypted hash.
#
# This currently fails if the responder attaches ANOTHER cert after the
# signature. WHY IS THIS ALLOWED?! ARHGLJ
#
# The above is a TODO
# @param ocsp_response - an OCSPResponse in DER format
# @param issuer_der_cert - the issuer's certificate in DER format
# @return NULL on failure or a string describing the verification state. Current options:
# 	- "Unhandled Signature Algorithm"
# 	- "Valid Signature"
# 	- "Invalid Signature"
#	- "Decryption Failed"
##
function verify_ocsp_response(ocsp_response, issuer_der_cert)
{
	local_var seq = der_decode(data:ocsp_response);
	if (isnull(seq) || seq[0] != 0x30) return NULL;
	seq = seq[1];

	# ResponseStatus - enumerated
	local_var resp_status = der_decode(data:seq);
	if (isnull(resp_status) || resp_status[0] != 0x0a || len(resp_status[1]) != 1) return NULL;
	if (resp_status[1] != '\x00') return NULL;

	# responseBytes[0]
	local_var responseBytes = der_decode(data:seq, pos:resp_status[2]);
	if (isnull(responseBytes) || responseBytes[0] != 0xa0) return NULL;

	# ResponseBytes sequence
	local_var responseBytesSeq = der_decode(data:responseBytes[1]);
	if (isnull(responseBytesSeq) || responseBytesSeq[0] != 0x30) return NULL;

	# verify that this is a basic ocsp response
	local_var responseType = der_decode(data:responseBytesSeq[1]);
	if (isnull(responseType) || responseType[0] != 6) return NULL;
	local_var responseOid = der_decode_oid(oid: responseType[1]);
	if (responseOid != "1.3.6.1.5.5.7.48.1.1") return NULL;

	# response - octet string
	local_var response = der_decode(data:responseBytesSeq[1], pos:responseType[2]);
	if (isnull(response) || response[0] != 4) return NULL;

	# first sequence in BasicOCSPResponse
	local_var response_seq = der_decode(data:response[1]);
	if (isnull(response_seq) || response_seq[0] != 0x30) return NULL;

	# ResponseData sequence
	local_var responseDataSeq = der_decode(data:response_seq[1]);
	if (isnull(responseDataSeq) || responseDataSeq[0] != 0x30) return NULL;

	local_var signature_algo_seq = der_decode(data:response_seq[1], pos:responseDataSeq[2]);
	if (isnull(signature_algo_seq) || signature_algo_seq[0] != 0x30) return NULL;

	# The algorithm used to sign the OCSPResponse hash
	local_var signature_algo = der_decode(data:signature_algo_seq[1]);
	if (isnull(signature_algo) || signature_algo[0] != 6) return NULL;
	local_var algorithm = der_decode_oid(oid:signature_algo[1]);
	if ("1.2.840." >!< algorithm) return ("Unhandled Signature Algorithm: " + algorithm);

	# These bytes are the signed hash of the OCSPResponse
	local_var signature_bits = der_decode(data:response_seq[1], pos:signature_algo_seq[2]);
	if (ord(signature_bits[1][0]) == 0)
	{
		signature_bits[1] = substr(signature_bits[1], 1, len(signature_bits[1]) - 1);
	}

	# The responder can chose to sign with a cert included at the end.
	local_var signer_cert = der_decode(data:response_seq[1], pos:signature_bits[2]);
	if (!isnull(signer_cert) && signer_cert[0] == 0xa0)
	{
		signer_cert = der_decode(data:signer_cert[1]);
		if (!isnull(signer_cert) && signer_cert[0] == 0x30) issuer_der_cert = signer_cert[1];
	}

	local_var parsed_issuer_cert = parse_der_cert(cert:issuer_der_cert);
	if (isnull(parsed_issuer_cert)) return NULL;

	local_var n = parsed_issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"][1][0];
	local_var e = parsed_issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"][1][1];
	if (isnull(n) || isnull(e)) return NULL;
	if (ord(n[0]) == 0) n = substr(n, 1, strlen(n) - 1);

	local_var decrypted = rsa_public_decrypt(sig:signature_bits[1], n:n, e:e);
	if (isnull(decrypted)) return "Decryption Failed";

	local_var hashed = NULL;
	local_var hash_this = substr(response_seq[1], 0, responseDataSeq[2] - 1);
	if (algorithm == "1.2.840.113549.1.1.11") hashed = SHA256(hash_this);
	else if(algorithm == "1.2.840.113549.1.1.5") hashed = SHA1(hash_this);
	else return ("Unhandled Signature Algorithm: " + algorithm);

	if (hashed >< decrypted) return "Valid Signature";
	return "Invalid Signature";
}

##
# Determines if the certificate supports OCSP or not.
#
# @param server_der_cert - the server's certificate in DER format
# @return TRUE if the certificate supports OCSP and FALSE otherwise
##
function has_ocsp(server_der_cert)
{
	local_var server_parsed_cert = parse_der_cert(cert:server_der_cert);
	if (isnull(server_parsed_cert)) return FALSE;

	local_var ocsp_location = get_ocsp_address(cert:server_parsed_cert);
	local_var crt_location = get_issuer_cert_address(cert:server_parsed_cert);
	return !isnull(ocsp_location) && !isnull(crt_location);
}

##
# Given a certificate, this function will determine if it has been revoked or not.
# Before calling this function, verify the cert supports OSCP via "has_ocsp".
#
# @param server_der_cert - the server's certificate in DER format
# @return NULL on failure or an two index array with the results. For example:
#	1. ['verify_ocsp_response': Valid Signature]['revocation_status': Not Revoked]
#   2. ['ocsp_failure': OCSP responder failed to respond.]
#   3. ['ocsp_failure': OCSP responder replied with a bad status: OCSPResponse is malformed]
#   4. ['ocsp_failure': Failed to download issuer cert.]
##
function do_ocsp(server_der_cert)
{
	// Use of 'target' without keepalive appears to be broken.
	http_disable_keep_alive();

	local_var server_parsed_cert = parse_der_cert(cert:server_der_cert);
	if (isnull(server_parsed_cert)) return NULL;

	local_var ocsp_location = get_ocsp_address(cert:server_parsed_cert);
	if (isnull(ocsp_location)) return NULL;

	local_var crt_location = get_issuer_cert_address(cert:server_parsed_cert);
	if (isnull(crt_location)) return NULL;

	local_var ocsp_fields = split_url(url:ocsp_location);
	if (isnull(ocsp_fields)) return NULL;

	local_var crt_fields = split_url(url:crt_location);
	if (isnull(crt_fields)) return NULL;

	// retrieve the the issuer certificate
	if (crt_fields["scheme"] != "https") crt_fields["scheme"] = NULL;
	if (isnull(crt_fields["page"])) crt_fields["page"] = "/";
	local_var res = http_send_recv3(
	  method: "GET",
	  transport: crt_fields["scheme"],
	  target: crt_fields["host"],
	  port: crt_fields["port"],
	  item: crt_fields["page"]);

	if (isnull(res) || "200 OK" >!< res[0] || isnull(res[2]))
	{
		return make_array('ocsp_failure', 'Failed to download issuer cert.');
	}
	local_var issuer_der_cert = res[2];

	// While this should be DER, we've seen PEM in the wild (GoDaddy). Check and
	// convert before sending on
	if ("-----BEGIN CERTIFICATE-----" >< issuer_der_cert)
	{
		issuer_der_cert = pem_to_blob(issuer_der_cert);
	}

	local_var ocsp_request = create_ocsp_request(server_der_cert:server_der_cert, issuer_der_cert:issuer_der_cert);
	if (isnull(ocsp_request)) return NULL;

	if (isnull(ocsp_fields["page"])) ocsp_fields["page"] = "/";
	res = http_send_recv3(
	  method: "POST",
	  target: ocsp_fields["host"],
	  port: ocsp_fields["port"],
	  item: ocsp_fields["page"],
	  content_type: "application/ocsp-request",
	  data: ocsp_request);

	if (isnull(res[2])) return make_array('ocsp_failure', 'OCSP responder failed to respond.');
	if (response_status_good(ocsp_response:res[2]) != TRUE)
	{
		return make_array('ocsp_failure',
			'OCSP responder replied with a bad status: ' + printable_status(ocsp_response:res[2]));
	}

	local_var revocation_status = get_revocation_status(ocsp_response:res[2], serial_number:server_parsed_cert["tbsCertificate"]["serialNumber"]);
	local_var verify_ocsp_response = verify_ocsp_response(ocsp_response:res[2], issuer_der_cert:issuer_der_cert);
	return make_array('revocation_status', revocation_status, 'verify_ocsp_response', verify_ocsp_response);
}
