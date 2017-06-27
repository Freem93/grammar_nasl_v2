#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  From: "Peter Winter-Smith" <peter4020@hotmail.com>
#  To: vuln@secunia.com
#  Cc: vulnwatch@vulnwatch.org
#  Date: Sat, 24 May 2003 09:15:47 +0000
#  Subject: [VulnWatch] P-News 1.16 Admin Access Vulnerability



include("compat.inc");

if(description)
{
 script_id(11669);
 script_version ("$Revision: 1.17 $");
 script_osvdb_id(53809);
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 script_name(english:"P-News p-news.php Name Field Privilege Escalation");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by a
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the p-news bulletin board. There is a 
flaw in the version in use which may allow an attacker who has a 
'Member' account to upgrade its privileges to administrator by 
supplying a malformed username." );
 script_set_attribute(attribute:"solution", value:
"Delete this CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of p-news.php");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(1, "The remote web server does not support PHP.");


function check(loc)
{
 local_var r, req;

 r = http_send_recv3(port:port, method:"GET", item:string(loc, "/p-news.php"));

 if( isnull(r) )exit(1,"Null response to p-news.php request.");
 if(egrep(pattern:"<title>P-News ver. (0\.|1\.([0-9][^0-9]|1[0-7]))", string:r[2]))
 {
   security_warning(port);
   exit(0);
 }
}

dirs = list_uniq(make_list("/news", cgi_dirs()));

foreach dir (dirs)
 check(loc:dir);
