#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(62969);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_cve_id("CVE-2012-4948");
  script_bugtraq_id(56382);
  script_osvdb_id(87048);
  script_xref(name:"CERT", value:"111708");

  script_name(english:"SSL Certificate Signed with the Compromised FortiGate Key");
  script_summary(english:"Checks if the certificate chain is signed by the FortiGate authority");

  script_set_attribute(attribute:"synopsis", value:
"The SSL certificate for this service was signed by a certificate
authority (CA) whose private key has been compromised.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host was signed by a certificate
belonging to a Certificate Authority (CA) found in FortiGate devices.
The private key corresponding to the CA has been compromised, meaning
that the remote host's X.509 certificate cannot be trusted.

Certificate chains descending from this CA could allow an attacker to
perform man-in-the-middle attacks and decode traffic.");
  script_set_attribute(attribute:"solution", value:
"Configure the device to use a device-specific CA certificate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:fortinet:fortigate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("Settings/ParanoidReport", "SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

# We only have the DN of the cert, which can easily collide with another
# certificate causing a false positive.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

# All the information we have is the DN of the FortiGate CA, which
# we'll create in the same format that we'll see it in a parsed cert.
fortigate =  make_nested_list(
  make_list(
    '2.5.4.6',
    'US'
  ),
  make_list(
    '2.5.4.8',
    'California'
  ),
  make_list(
    '2.5.4.7',
    'Sunnyvale'
  ),
  make_list(
    '2.5.4.10',
    'Fortinet'
  ),
  make_list(
    '2.5.4.11',
    'Certificate Authority'
  ),
  make_list(
    '2.5.4.3',
    'FortiGate CA'
  ),
  make_list(
    '1.2.840.113549.1.9.1',
    'support@fortinet.com'
  )
);

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
# certificate in the chain was issued by a certificate with a
# Distinguished Name that matches the FortiGate CA.
#
# We don't know if the FortiGate device includes its own certificate
# in the chain when it man-in-the-middles a connection, so we can't
# look for the FortiGate CA's public key (even if we knew it). This
# means that false positives are possible if there is a
# device-specific CA created with the same Distinguished Name.
top = chain[max_index(chain) - 1];
top = top["tbsCertificate"];

if (!obj_cmp(top["issuer"], fortigate))
  exit(0, "The certificate chain from port " + port + " is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  cert = chain[0];
  cert = cert["tbsCertificate"];

  report =
    '\nThe following certificate has been issued by a certificate' +
    '\nauthority whose private key has been compromised :' +
    '\n' +
    '\n  Subject : ' + format_dn(cert["subject"]) +
    '\n  Issuer  : ' + format_dn(cert["issuer"]) +
    '\n';
}

security_warning(port:port, extra:report);
