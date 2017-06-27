#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15540);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_cve_id("CVE-2002-0230", "CVE-2002-2011");
  script_bugtraq_id(4565);
  script_osvdb_id(8661, 54110);

  script_name(english:"Faq-O-Matic fom.cgi Multiple Parameter XSS");
  script_summary(english:"Checks Faq-O-Matic XSS");

  script_set_attribute(attribute:"synopsis", value:"A web CGI is vulnerable to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host runs Faq-O-Matic, a CGI-based system that automates
the process of maintaining a FAQ.

The remote version of this software is vulnerable to cross-site
scripting attacks in the script 'fom.cgi'.

With a specially crafted URL, an attacker can cause arbitrary code
execution resulting in a loss of integrity.");
  script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_dependencie("cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: avoid false-posiives caused by not checking for the app itself.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);


function check(req)
{
  local_var buf, r;
  buf = http_get(item:string(req,"/fom/fom.cgi?cmd=<script>foo</script>&file=1&keywords=nessus"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
}

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
foreach dir (cgi_dirs()) check(req:dir);
