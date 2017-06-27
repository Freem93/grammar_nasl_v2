#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66848);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/10 14:29:42 $");

  script_name(english:"SSL Null Cipher Suites Supported");
  script_summary(english:"Reports any null SSL cipher suites that are supported");

  script_set_attribute(attribute:"synopsis", value:"The remote service supports the use of null SSL ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer no
encryption at all. 

Note: This is considerably easier to exploit if the attacker is on the
same physical network.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application, if possible to avoid the use of
null ciphers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/10");

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
supported_ciphers = make_list(supported_ciphers);
if (!max_index(supported_ciphers)) exit(0, "No ciphers were found for port " + port + ".");

# Generate the report of supported null ciphers.
report = cipher_report(supported_ciphers, eq:CIPHER_STRENGTH_NULL);
if (isnull(report)) exit(0, "No null SSL ciphers are supported on port " + port + ".");

if (report_verbosity > 0)
{
  report =
    '\nHere is the list of null SSL ciphers supported by the remote server :' +
    '\n' + report;

  security_warning(port:port, extra:report);
}
else security_warning(port);
