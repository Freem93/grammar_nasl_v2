#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16250);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2005-0310");
 script_bugtraq_id(12358);
 script_osvdb_id(13189);
 script_xref(name:"Secunia", value:"13988");

 script_name(english:"Exponent CMS Multiple Script pathos_core_version Parameter Path Disclosure");
 script_summary(english:"Checks for the version of Exponent");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has an information
disclosure vulnerability." );
 script_set_attribute( attribute:"description", value:
"The remote host is running Exponent, a web-based content management
system implemented in PHP.

Directly requesting several different pages reveals the absolute path
where Exponent is installed.  A remote attacker could use this
information to mount further attacks.

In addition, the installed version is likely to be affected to
multiple cross-site scripting vulnerabilities, although Nessus has not
checked for them." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/296"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Exponent 0.96 beta5 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/25");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
  
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 
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
if(!can_host_php(port:port)) exit(0);

function check(dir)
{
local_var r, req;
req = string(dir, "/subsystems/permissions.info.php");
r = http_send_recv3(method:"GET", item:req, port:port);
if ( isnull(r) ) exit(0);

if ( egrep(pattern:"<b>Fatal error</b>:  Call to undefined function:  pathos_core_version()", string:r[2]))
 {
 security_warning(port);
 exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(dir:dir);
}
