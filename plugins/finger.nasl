#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10068);
 script_version ("$Revision: 1.37 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_cve_id("CVE-1999-0612");
 script_osvdb_id(11451);

 script_name(english:"Finger Service Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain information about the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the 'finger' service. 

The purpose of this service is to show who is currently logged into
the remote system, and to give information about the users of the
remote system. 
 
It provides useful information to attackers, since it allows them to
gain usernames, determine how used a machine is, and see when each
user logged in for the last time." );
 script_set_attribute(attribute:"solution", value:
"Comment out the 'finger' line in /etc/inetd.conf and restart the 
inetd process" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1992/01/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for finger");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("Services/finger");
if(!port){ port = 79; reg = TRUE; }
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("root\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  if(egrep(pattern:".*User|[lL]ogin|logged.*", string:data))
  {
   report = 'Here is the output we obtained for \'root\' : \n\n' + data + '\n';

   security_warning(port:port, extra:report);
   set_kb_item(name:"finger/active", value:TRUE);
   if ( reg ) register_service(proto:"finger", port:port);
  }

  close(soc);
 }
}
