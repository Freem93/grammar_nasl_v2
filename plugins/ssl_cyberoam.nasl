#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(61447);
  script_version ("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/09/13 19:11:08 $");

  script_cve_id("CVE-2012-3372");
  script_bugtraq_id(54291);
  script_osvdb_id(83532);

  script_name(english:"SSL Certificate Signed with the Publicly Known Cyberoam Key");
  script_summary(english:"Checks if the certificate chain is signed by the Cyberoam authority");

  script_set_attribute(attribute:"synopsis", value:
"The SSL certificate for this service was signed by a CA whose private
key is public knowledge.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host was signed by a certificate
belonging to a Certificate Authority (CA) found in Cyberoam devices. 
The private key corresponding to the CA was discovered and publicly
disclosed, meaning that the remote host's X.509 certificate cannot be
trusted.");
  script_set_attribute(attribute:"see_also", value:"https://media.torproject.org/misc/2012-07-03-cyberoam-CVE-2012-3372.txt");
  # https://blog.torproject.org/blog/security-vulnerability-found-cyberoam-dpi-devices-cve-2012-3372
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c356aec");
  # http://blog.cyberoam.com/2012/07/cyberoam%E2%80%99s-proactive-steps-in-https-deep-scan-inspection/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?956bd276");
  script_set_attribute(attribute:"see_also", value:"http://blog.cyberoam.com/2012/07/ssl-bridging-cyberoam-approach/");
  script_set_attribute(attribute:"solution", value:"Configure the device to use a device-specific CA certificate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:elitecore:cyberoam_unified_threat_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

# Parse the Cyberoam certificate before forking.
cyberoam = "
MIIFADCCA+igAwIBAgIJAKa1LpKB0iJiMA0GCSqGSIb3DQEBBQUAMIGwMQswCQYD
VQQGEwJJTjEQMA4GA1UECBMHR3VqYXJhdDESMBAGA1UEBxMJQWhtZWRhYmFkMRIw
EAYDVQQKEwlFbGl0ZWNvcmUxJzAlBgNVBAsTHkN5YmVyb2FtIENlcnRpZmljYXRl
IEF1dGhvcml0eTEYMBYGA1UEAxMPQ3liZXJvYW0gU1NMIENBMSQwIgYJKoZIhvcN
AQkBFhVzdXBwb3J0QGVsaXRlY29yZS5jb20wHhcNMTAwNTEwMDc1NjA0WhcNMzYx
MjMxMDc1NjA0WjCBsDELMAkGA1UEBhMCSU4xEDAOBgNVBAgTB0d1amFyYXQxEjAQ
BgNVBAcTCUFobWVkYWJhZDESMBAGA1UEChMJRWxpdGVjb3JlMScwJQYDVQQLEx5D
eWJlcm9hbSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxGDAWBgNVBAMTD0N5YmVyb2Ft
IFNTTCBDQTEkMCIGCSqGSIb3DQEJARYVc3VwcG9ydEBlbGl0ZWNvcmUuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4ax+WmILhtQDBuW1VAY3gAKo
OBGLD34GyKXHBKepRDLgn7n/3sYuXj4D8Og9sjhdBuw+o+jji2IFtZVbMjas6NU2
BIX8dynmtmTn//d6ACALXEmD6JVP2Wqw+/ZxCQaf+JmPz9zX/6r2y8VpB1b9w1pE
jQTUmAh9yexeWiGX+d0/XvkO+pAFCB8pYUYmU0AiXsU2XqZMj09rMw6tgaQkrQPP
2N/op8qwT+4U35UaexCxjntaSqnoT3ulsTB+adlWcI2VP/+Lg43sW+TIe9EVu09Z
W4BBQ2OjlqSHeVtWfeVwZySrgtyQU7FvDKJeMnGNc/vDlax1+9/zXU7wyyPd5QID
AQABo4IBGTCCARUwHQYDVR0OBBYEFMaO7snsjSZzegkSuHPxvq+3ZYjhMIHlBgNV
HSMEgd0wgdqAFMaO7snsjSZzegkSuHPxvq+3ZYjhoYG2pIGzMIGwMQswCQYDVQQG
EwJJTjEQMA4GA1UECBMHR3VqYXJhdDESMBAGA1UEBxMJQWhtZWRhYmFkMRIwEAYD
VQQKEwlFbGl0ZWNvcmUxJzAlBgNVBAsTHkN5YmVyb2FtIENlcnRpZmljYXRlIEF1
dGhvcml0eTEYMBYGA1UEAxMPQ3liZXJvYW0gU1NMIENBMSQwIgYJKoZIhvcNAQkB
FhVzdXBwb3J0QGVsaXRlY29yZS5jb22CCQCmtS6SgdIiYjAMBgNVHRMEBTADAQH/
MA0GCSqGSIb3DQEBBQUAA4IBAQC3Q8fUg8iAUL2Q01o6GXjThzSI1C95qJK3FAlG
q/XZzhJlJfxHa3rslcDrbNkAdKCnthpF07xYBbAvh0cIn0ST98/2sHJDJ4sg3Pqp
HUtNOL3PpNMgdqXtoQgKcm8XtkBOppGrCR4HTcRjf0ZLfWP71S3/Ne1o1U10KrPh
LWGYME+4Uh6lo7OBdZp8C8IjPYT2GSCquh/wWrtSYspfO4HJw/5dXaY7wfTh8P0k
/ENLBUUzENiiDiyhXKEZvCAbX+KWNq2T4w7r+411ycV828cuwZx/MehWQrw2SpjC
3sVdb7GwxgxcyGE6TM39Ht3Jl4scTFmKZrG8A9BwTYQsvm6I";

cyberoam = str_replace(string:cyberoam, find:'\n', replace:"");
cyberoam = base64_decode(str:cyberoam);
cyberoam = parse_der_cert(cert:cyberoam);
cyberoam = cyberoam["tbsCertificate"];

if (isnull(cyberoam))
  exit(1, "Failed to parse builtin certificate.");

# Get list of ports that use SSL or StartTLS.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Get the certificate chain from the target.
chain = get_server_cert(
  port     : port,
  encoding : "der",
  getchain : TRUE
);
if (isnull(chain) || max_index(chain) <= 0)
  exit(1, "Failed to retrieve the certificate chain from port " + port + ".");

chain = parse_cert_chain(chain);
if (isnull(chain))
  exit(1, "Failed to parse certificate chain on port " + port + ".");

# The offending certificate is self-signed, meaning that it can only
# occur at the top of the certificate chain. Check that the top
# certificate in the chain was issued by the offending certificate,
# and that its public key matches to avoid other certs with the same
# Distinguished Name.
#
# We know from screenshots of affected SSL connections that the device
# includes its CA certificate as part of the chain.
top = chain[max_index(chain) - 1];
top = top["tbsCertificate"];

if (
  !is_signed_by(top, cyberoam) ||
  !obj_cmp(top["subjectPublicKeyInfo"], cyberoam["subjectPublicKeyInfo"])
) exit(0, "The certificate chain from port " + port + " is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  cert = chain[0];
  cert = cert["tbsCertificate"];

  report =
    '\nThe following certificate has been issued by a certificate' +
    '\nauthority whose private key is public knowledge :' +
    '\n' +
    '\n  Subject : ' + format_dn(cert["subject"]) +
    '\n  Issuer  : ' + format_dn(cert["issuer"]) +
    '\n';
}

security_warning(port:port, extra:report);
