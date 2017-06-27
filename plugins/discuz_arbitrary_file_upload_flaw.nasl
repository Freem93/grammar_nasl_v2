#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19751);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");

 script_cve_id("CVE-2005-2614");
 script_bugtraq_id(14564);
 script_osvdb_id(18771);
 
 script_name(english:"Discuz! <= 4.0.0 rc4 Arbitrary File Upload");
 script_summary(english:"Checks Discuz! version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary file upload issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is using Discuz!, a popular web application forum in
China. 

According to its version, the installation of Discuz! on the remote
host fails to properly check for multiple extensions in uploaded
files.  An attacker may be able to exploit this issue to execute
arbitrary commands on the remote host subject to the privileges of the
web server user id.");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/fulldisclosure/2005/Aug/438");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");

global_var port;

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

function check(loc)
{
 local_var r, req;

 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( isnull(r) )exit(1, "The web server on port "+port+" failed to respond.");
 if (("powered by Discuz!</title>" >< r) && egrep(pattern:'<meta name="description" content=.+Powered by Discuz! Board ([1-3]|4\\.0\\.0RC[0-4])', string:r))
 {
   security_warning(port);
   exit(0);
 }
}

if (thorough_tests) dirs = list_uniq(make_list("/discuz", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
