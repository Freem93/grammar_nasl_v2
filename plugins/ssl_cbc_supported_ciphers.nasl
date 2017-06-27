#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70544);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/22 14:45:25 $");

  script_name(english:"SSL Cipher Block Chaining Cipher Suites Supported");
  script_summary(english:"Reports any SSL CBC cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of SSL Cipher Block Chaining
ciphers, which combine previous blocks with subsequent ones.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that operate in Cipher
Block Chaining (CBC) mode.  These cipher suites offer additional
security over Electronic Codebook (ECB) mode, but have the potential to
leak information if used improperly.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html");
  # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc4a822a");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

supported_ciphers = get_kb_list_or_exit("SSL/Ciphers/" + port);

# Generate the report of supported CBC ciphers.
report = cipher_report(supported_ciphers, name:"_CBC_");
if (isnull(report)) exit(0, "No SSL CBC ciphers are supported on port " + port + ".");

if (report_verbosity > 0)
{
  report =
    '\nHere is the list of SSL CBC ciphers supported by the remote server :' +
    '\n' + report;
  security_note(port:port, extra:report);
}
else security_note(port);
