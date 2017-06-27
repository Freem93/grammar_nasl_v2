#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83738);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/16 15:48:33 $");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_osvdb_id(122331);

  script_name(english:"SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)");
  script_summary(english:"The remote host supports a weak set of ciphers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host supports a set of weak ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports EXPORT_DHE cipher suites with keys less than
or equal to 512 bits. Through cryptanalysis, a third party can find
the shared secret in a short amount of time.

A man-in-the middle attacker may be able to downgrade the session to
use EXPORT_DHE cipher suites. Thus, it is recommended to remove
support for weak cipher suites.");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the service to remove support for EXPORT_DHE cipher
suites.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
if (isnull(port)) audit(AUDIT_HOST_NONE, "SSL-based services");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

supported_ciphers = get_kb_list_or_exit("SSL/Ciphers/" + port);
supported_ciphers = make_list(supported_ciphers);
if (!max_index(supported_ciphers)) exit(0, "No ciphers were found for port " + port + ".");

c_report = cipher_report(supported_ciphers, name:"_CK_DHE?_.*_EXPORT_");

if (isnull(c_report)) exit(0, "No EXPORT_DHE cipher suites are supported on port " + port + ".");

# Report our findings.
if (report_verbosity > 0)
{
  report =
    '\nEXPORT_DHE cipher suites supported by the remote server :' +
    '\n' + c_report;
  security_note(port:port, extra:report);
}
else security_note(port);
