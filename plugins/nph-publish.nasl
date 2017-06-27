#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin description, removed invalid CVE, added OSVDB (4/21/009)

include("compat.inc");

if (description)
{
 script_id(10164);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2014/05/26 01:40:12 $");

 script_cve_id("CVE-1999-1177");
 script_osvdb_id(127);

 script_name(english:"Lincoln D. Stein nph-publish.cgi pathname Parameter Traversal Arbitrary File Write");
 script_summary(english:"Checks for the presence of /cgi-bin/nph-publish.cgi");

 script_set_attribute(attribute:"synopsis", value:"It may be possible to run arbitrary commands on the remote host.");
 script_set_attribute(attribute:"description", value:
"The 'nph-publish.cgi' is installed. This CGI has a well known security
flaw that lets an attacker to execute arbitrary commands with the
privileges of the HTTP daemon (usually root or nobody).");
 script_set_attribute(attribute:"solution", value:"Remove it from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/03/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/12/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Mathieu Perrin");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"nph-publish.cgi");
if( res )security_hole(port);
