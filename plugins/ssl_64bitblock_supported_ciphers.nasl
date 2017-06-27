#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94437);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/24 14:51:33 $");

  script_cve_id("CVE-2016-2183", "CVE-2016-6329");
  script_bugtraq_id(92630, 92631);
  script_osvdb_id(143387, 143388);

  script_name(english:"SSL 64-bit Block Size Cipher Suites Supported (SWEET32)");
  script_summary(english:"Reports any 3DES, RC2, or other 64-bit block cipher suites that are supported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of 64-bit block ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of a block cipher with 64-bit blocks
in one or more cipher suites. It is, therefore, affected by a
vulnerability, known as SWEET32, due to the use of weak 64-bit block
ciphers. A man-in-the-middle attacker who has sufficient resources can
exploit this vulnerability, via a 'birthday' attack, to detect a
collision that leaks the XOR between the fixed secret and a known
plaintext, allowing the disclosure of the secret text, such as secure
HTTPS cookies, and possibly resulting in the hijacking of an
authenticated session.

Proof-of-concepts have shown that attackers can recover authentication
cookies from an HTTPS session in as little as 30 hours.

Note that the ability to send a large number of requests over the
same TLS connection between the client and server is an important
requirement for carrying out this attack. If the number of requests
allowed for a single connection were limited, this would mitigate the
vulnerability. However, Nessus has not checked for such a mitigation.");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application, if possible, to avoid use of all
64-bit block ciphers. Alternatively, place limitations on the number
of requests that are allowed to be processed over the same TLS
connection to mitigate this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

report = NULL;

# _28147_ is the 64-bit block cipher from the GOST standards
ciphers_supported = cipher_report(supported_ciphers, name:"_(3DES|RC2|IDEA|28147)_");
if (isnull(ciphers_supported))
  exit(0, "No 64-bit block cipher suites are supported on port " + port + ".");

report =
  '\nList of 64-bit block cipher suites supported by the remote server :' +
  '\n' + ciphers_supported;

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
