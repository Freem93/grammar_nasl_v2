#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID

# Changes by Tenable:
# - use ereg() insted of ><  (RD)
# - revised plugin title, added OSVDB ref, enhanced description (4/3/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(10416);
 script_version ("$Revision: 1.26 $");
 script_bugtraq_id(2255);
 script_osvdb_id(318);

 script_name(english:"Sambar Server /sysadmin Default Accounts");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server can be accessed with default credentials." );
 script_set_attribute(attribute:"description", value:
"The Sambar webserver is running.
It provides a web interface for configuration purposes.
The admin user has no password and there are some other 
default users without passwords.
Everyone could set the HTTP-Root to c:\ and delete your files!

*** this may be a false positive - go to http://the_server/sysadmin/ 
and verify it yourself." );
 script_set_attribute(attribute:"solution", value:
"Change the passwords via the webinterface" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");


 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/06/10");
 script_cvs_date("$Date: 2015/10/09 22:45:48 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"default_account", value:"true");
script_end_attributes();

 
 script_summary(english:"Sambar webserver installed ?");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2015 Hendrik Scholz");

 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 3135);
 script_require_keys("www/sambar");
 
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:3135);
foreach port (ports)
{
 data = http_get(item:"/sysadmin/dbms/dbms.htm", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:4096);
  buf2 = http_recv(socket:soc);
  http_close_socket(soc);
  if(egrep(pattern:"[sS]ambar", string:buf))
  {
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 403 ", string:buf))security_hole(port);
  }
 }
}

