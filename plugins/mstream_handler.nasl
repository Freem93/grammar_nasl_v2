#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10391);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");
 script_cve_id("CVE-2000-0138");
 script_osvdb_id(295);

 script_name(english:"mstream DDoS Handler Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to have a suspicious program installed." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a mstream handler, which is a
trojan that can be used to control your system or make it attack 
another network (this is actually called a distributed denial of 
service attack tool)

It is very likely that this host has been compromised" );
 script_set_attribute(attribute:"solution", value:
"Restore your system from known good backups or re-install the
operating system." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Detects the presence of a mstream agent");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2013 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_require_ports(6723, 15104, 12754); 
 script_dependencies("find_service1.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#

include("misc_func.inc");
include('global_settings.inc');
if ( islocalhost() ) exit(0);
if (!  thorough_tests ) exit(0);


function check(port, pass)
{
 local_var r, soc;
 if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:string(pass, "\r\n"));
  r = recv(socket:soc, length:2, timeout:2);
  close(soc);
  if(r == "> ")
	{
  	security_warning(port);
  	return(1);
	}
  }
 }
  return(0);
}

port = get_unknown_svc();
if(port)
{
 if(check(port:port, pass:"sex"))exit(0);
 if(check(port:port, pass:"N7%diApf!"))exit(0);
}
else
{
 if(check(port:6723, pass:"sex"))exit(0);
 if(check(port:15104, pass:"N7%diApf!"))exit(0);
 if(check(port:12754, pass:"N7%diApf!"))exit(0);
}
