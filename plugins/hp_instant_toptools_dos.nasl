#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11520);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2003-0169");
 script_bugtraq_id(7246);
 script_osvdb_id(6666);
 
 script_name(english:"HP Instant TopTools hpnst.exe CGI DoS");
 script_summary(english:"Checks for hpnst.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host has the CGI 'hpnst.exe' installed.

Older versions of this CGI (pre 5.55) are vulnerable
to a denial of service attack where the user can make
the CGI request itself." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q1/162" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version HP TopTools 5.55 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/31");
 script_set_attribute(attribute:"patch_publication_date", value: "2003/03/25");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:instant_toptools");
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(safe_checks() == 0)
{
 foreach dir (cgi_dirs())
 {
   if (http_is_dead(port:port)) exit(0);
   res = http_send_recv3(method:"GET", item:string(dir, "/hpnst.exe?c=p+i=hpnst.exe"), port:port);
   if(isnull(res) && http_is_dead(port:port)){ security_warning(port); exit(0); }
 }
 
exit(0);
}
