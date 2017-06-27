#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/16/009)

include("compat.inc");

if (description)
{
 script_id(10099);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2014/05/26 00:12:07 $");

 script_cve_id("CVE-1999-1053");
 script_bugtraq_id(776);
 script_osvdb_id(84);

 script_name(english:"Matt Wright guestbook.pl Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/guestbook.pl");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The 'guestbook.pl' is installed. This CGI has a well known security
flaw that lets anyone execute arbitrary commands with the privileges
of the HTTP daemon (root or nobody).");
 script_set_attribute(attribute:"solution", value:"Remove the affected script.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Matt Wright guestbook.pl Arbitrary Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/12/01");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Mathieu Perrin");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
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
res = is_cgi_installed_ka(item:"guestbook.pl", port:port);
if(res)security_hole(port);


