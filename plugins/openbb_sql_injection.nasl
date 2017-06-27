#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# From: Albert Puigsech Galicia <ripe@7a69ezine.org>
# Organization: 7a69
# To: bugtraq@securityfocus.com
# Subject: Multiple SQL injection on OpenBB forums

include("compat.inc");

if(description)
{
 script_id(11550);
 script_version("$Revision: 1.18 $");

 script_bugtraq_id(7401);
 script_osvdb_id(3342);
 
 script_name(english:"OpenBB index.php CID Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an application that is affected by
a SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running OpenBB, a forum management
system.

There is a bug which allows an attacker to inject SQL command
when passing a single quote (') to the CID argument of the
file index.php, as in : GET /index.php?CID='<sql query>

An attacker may use this flaw to gain credentials or to modify
your database." );
 script_set_attribute(attribute:"solution", value:
"If the remote host is running OpenBB, 
upgrade to the latest version" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/25");
 script_cvs_date("$Date: 2011/03/12 01:05:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Tests for SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
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
if(!can_host_php(port:port))exit(0,"The remote web server does not support PHP.");

foreach d (list_uniq(make_list( "/openbb", cgi_dirs())))
{
  res = http_send_recv3(method:"GET", item:string(d,"/index.php?CID='"), port:port);
  if( isnull(res) ) exit(1,"Null response for index.php request.");
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res[0]) &&
    egrep(pattern:"SELECT guest, forumid, title, lastthread, lastposter, lastposterid, lastthreadid, lastpost, moderators, description, type, postcount, threadcount", string:res[2]))
    {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
   }
}
