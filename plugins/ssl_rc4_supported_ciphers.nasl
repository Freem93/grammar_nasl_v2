#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65821);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2013-2566", "CVE-2015-2808");
  script_bugtraq_id(58796, 73684);
  script_osvdb_id(91162, 117855);

  script_name(english:"SSL RC4 Cipher Suites Supported (Bar Mitzvah)");
  script_summary(english:"Reports any RC4 cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of the RC4 cipher.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of RC4 in one or more cipher suites.
The RC4 cipher is flawed in its generation of a pseudo-random stream
of bytes so that a wide variety of small biases are introduced into
the stream, decreasing its randomness.

If plaintext is repeatedly encrypted (e.g., HTTP cookies), and an
attacker is able to obtain many (i.e., tens of millions) ciphertexts,
the attacker may be able to derive the plaintext.");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application, if possible, to avoid use of RC4
ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser
and web server support.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217a3666");
  script_set_attribute(attribute:"see_also", value:"http://cr.yp.to/talks/2013.03.12/slides.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.isg.rhul.ac.uk/tls/");
  script_set_attribute(attribute:"see_also", value:"http://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

# Generate the report of supported RC4 ciphers.
c_report = cipher_report(supported_ciphers, name:"_RC4_");
if (isnull(c_report)) exit(0, "No RC4 cipher suites are supported on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nList of RC4 cipher suites supported by the remote server :' +
    '\n' + c_report;
}
security_note(port:port, extra:report);
