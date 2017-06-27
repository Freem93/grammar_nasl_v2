#
# (C) Tenable Network Security, Inc.
#
# Starting with Nessus 3.2.1, this script replaces 
# ssl_ciphers.nes
#

# Check if this version of nessusd is too old
if ( NASL_LEVEL < 3208 ) exit(0);


include("compat.inc");

if (description)
{
 script_id(10863);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/12/30 17:04:09 $");
 
 script_name(english:"SSL Certificate Information");
 script_summary(english:"Displays the server SSL/TLS certificate");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin displays the SSL certificate.");
 script_set_attribute(attribute:"description", value:
"This plugin connects to every SSL-related port and attempts to 
extract and dump the X.509 certificate.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert)) exit(1, "Failed to read the certificate for the service listening on port "+port+".");

# calculate fingerprints on raw certificate
fingerprints = 'Fingerprints : \n\n' +
add_hex_string(name:"SHA-256 Fingerprint", data:SHA256(cert)) + 
add_hex_string(name:"SHA-1 Fingerprint", data:SHA1(cert)) + 
add_hex_string(name:"MD5 Fingerprint", data:MD5(cert)) + '\n';

cert = parse_der_cert(cert:cert);
if (isnull(cert)) exit(1, "Failed to parse the certificate from the service listening on port "+port+".");

report = dump_certificate(cert:cert);
if (!report) exit(1, "Failed to dump the certificate from the service listening on port "+port+".");

report += fingerprints;

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
