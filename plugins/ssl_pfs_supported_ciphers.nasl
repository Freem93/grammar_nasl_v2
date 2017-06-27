#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57041);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2012/04/02 16:34:10 $");

  script_name(english:"SSL Perfect Forward Secrecy Cipher Suites Supported");
  script_summary(english:"Reports any SSL PFS cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of SSL Perfect Forward Secrecy
ciphers, which maintain confidentiality even if the key is stolen.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer Perfect
Forward Secrecy (PFS) encryption.  These cipher suites ensure that
recorded SSL traffic cannot be broken at a future date if the server's
private key is compromised.");

  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Perfect_forward_secrecy");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

supported_ciphers = get_kb_list_or_exit("SSL/Ciphers/" + port);

# Generate the report of supported PFS ciphers.
report = cipher_report(supported_ciphers, name:"_(EC)?(DHE|EDH)_");
if (isnull(report)) exit(0, "No SSL PFS ciphers are supported on port " + port + ".");

if (report_verbosity > 0)
{
  report =
    '\nHere is the list of SSL PFS ciphers supported by the remote server :' +
    '\n' + report;
  security_note(port:port, extra:report);
}
else security_note(port);
