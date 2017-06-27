#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14370);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2004-2704");
 script_bugtraq_id(11022);
 script_osvdb_id(9131);
 script_xref(name:"Secunia", value:"12358");
 
 script_name(english:"HastyMail HTML Attachment Script Execution");
 script_summary(english:"Checks for version of HastyMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HastyMail, a PHP-based mail client
application.

The installed version contains a flaw caused by email attachments not
being properly defined int he Content-Disposition HTTP header. An
attacker could exploit this flaw to inject Javascript or ActiveX code
in an attachment." );
 script_set_attribute(attribute:"see_also", 
   value:"http://seclists.org/bugtraq/2004/Aug/326" 
 );
 script_set_attribute(attribute:"solution", value:
"Upgrade to HastyMail 1.0.2 or 1.2.0, as this reportedly fixes the
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/24");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r;

 r = http_send_recv3(method: "GET", item:string(loc, "/login.php"), port:port);
 if (isnull(r)) exit(0);
 if("Hastymail" >< r[2] && egrep(pattern:"Hastymail (0\.|1\.0\.[01]|1\.1\.)", string: r[2]) )
 {
 	security_warning(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

