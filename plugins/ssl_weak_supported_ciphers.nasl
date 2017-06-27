#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26928);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"SSL Weak Cipher Suites Supported");
  script_summary(english:"Reports any weak SSL cipher suites that are supported");

  script_set_attribute(attribute:"synopsis", value:"The remote service supports the use of weak SSL ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer weak
encryption. 

Note: This is considerably easier to exploit if the attacker is on the
same physical network.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application, if possible to avoid the use of
weak ciphers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(
    326, # Inadequate Encryption Strength
    327, # Use of a Broken or Risky Cryptographic Algorithm
    720, # OWASP Top Ten 2007 Category A9 - Insecure Communications
    753, # 2009 Top 25 - Porous Defenses
    803, # 2010 Top 25 - Porous Defenses
    928, # Weaknesses in OWASP Top Ten 2013
    934  # OWASP Top Ten 2013 Category A6 - Sensitive Data Exposure
  );
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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
supported_ciphers = make_list(supported_ciphers);
if (!max_index(supported_ciphers)) exit(0, "No ciphers were found for port " + port + ".");

# Generate the report of supported weak ciphers.
report = cipher_report(supported_ciphers, eq:CIPHER_STRENGTH_LOW);
if (isnull(report)) exit(0, "No weak SSL ciphers are supported on port " + port + ".");

if (report_verbosity > 0)
{
  report =
    '\nHere is the list of weak SSL ciphers supported by the remote server :' +
    '\n' + report;

  security_warning(port:port, extra:report);
}
else security_warning(port);
