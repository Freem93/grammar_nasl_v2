#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/9/2009)


include("compat.inc");

if (description)
{
 script_id(10570);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2014/05/25 23:51:31 $");

 script_cve_id("CVE-2000-1024");
 script_bugtraq_id(1876);
 script_osvdb_id(469);

 script_name(english:"Unify eWave ServletExec 3.0C UploadServlet Unprivileged File Upload");
 script_summary(english:"Unify eWave ServletExec 3.0C file upload");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary files may be overwritten on the remote host.");
 script_set_attribute(attribute:"description", value:
"ServletExec has a servlet called 'UploadServlet' in its server side
classes. UploadServlet, when invokable, allows an attacker to upload
any file to any directory on the server. The uploaded file may have
code that can later be executed on the server, leading to remote
command execution.");
 script_set_attribute(attribute:"solution", value:"Remove it.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/12/19");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Matt Moore");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
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
res = is_cgi_installed_ka(item:"/servlet/nessus." + string(rand(),rand(), rand()), port:port);
if ( res ) exit(0);

res = is_cgi_installed_ka(item:"/servlet/com.unify.servletexec.UploadServlet", port:port);
if(res)
{
 security_hole(port);
}

