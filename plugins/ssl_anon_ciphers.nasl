#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31705);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2007-1858");
  script_bugtraq_id(28482);
  script_osvdb_id(34882);

  script_name(english:"SSL Anonymous Cipher Suites Supported");
  script_summary(english:"Reports anonymous SSL ciphers suites that are supported");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of anonymous SSL ciphers." );
 script_set_attribute(attribute:"description", value:
"The remote host supports the use of anonymous SSL ciphers.  While this
enables an administrator to set up a service that encrypts traffic
without having to generate and configure SSL certificates, it offers
no way to verify the remote host's identity and renders the service
vulnerable to a man-in-the-middle attack.

Note: This is considerably easier to exploit if the attacker is on the
same physical network." );
 script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html" );
 script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application if possible to avoid use of weak
ciphers." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/28");
 script_cvs_date("$Date: 2014/01/27 00:51:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/09");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
 
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

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

# Generate the report of supported anonymous ciphers.
report = cipher_report(supported_ciphers, desc:"Au=None");
if (isnull(report)) exit(0, "No SSL anonymous ciphers are supported on port " + port + ".");

if (report_verbosity > 0)
{
  report =
    '\nHere is the list of SSL anonymous ciphers supported by the remote server :' +
    '\n' + report;
  security_note(port:port, extra:report);
}
else security_note(port);
