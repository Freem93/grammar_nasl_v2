#
# (C) Tenable Network Security, Inc.
#

# This script is based on BEA_weblogic_Reveal_source_code.nasl
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#


include("compat.inc");

if(description)
{
script_id(11604);
script_cve_id("CVE-2000-0683");
script_bugtraq_id(1517);
  script_osvdb_id(1480);
script_version("$Revision: 1.22 $");

script_name(english:"BEA WebLogic SSIServlet Invocation Source Code Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"BEA WebLogic may be tricked into revealing the source code of JSP
scripts by prefixing the path to the .jsp files by /*.shtml/" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jul/411" );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/wls-security/12.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate Service Pack according to the referenced
vendor advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/31");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


summary["english"]="BEA WebLogic may be tricked into revealing the source code of JSP scripts.";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is (C) 2003-2016 Tenable Network Security, Inc.");

script_family(english:"CGI abuses");

script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");


exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(req, port)
{ 
local_var r, response, signature;
r = http_send_recv3(method:"GET", item:req, port:port); 
if (isnull(r)) return 0;

response = strcat(r[0], r[1], '\r\n', r[2]);

#signature of Jsp.

signature = "<%=";

if (signature >< response) return(1);
 
return(0);
}


port = get_http_port(default:80, embedded: 0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);

# Try with a known jsp file

files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(isnull(files))file = "/index.jsp";
else
 {
 files = make_list(files);
 file = files[0];
 }
 
if(check(req:string("/*.shtml/", file), port:port))security_warning(port);
