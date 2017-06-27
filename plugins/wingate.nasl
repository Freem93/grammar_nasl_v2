#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10309);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_cve_id("CVE-1999-0291");
  script_osvdb_id(245);

  script_name(english:"WinGate Passwordless Default Installation");
  script_summary(english:"Determines if wingate is installed");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service may allow an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"Wingate is a program that allows
a Windows98 computer to act as a proxy.
Unfortunately, the default configuration is too
permissive and allows anyone to use this computer
to connect anywhere, thus hiding the real IP address.

This WinGate server does not ask for any
passwords, and thus can be used by an attacker
from anywhere as a telnet relay."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Adjust the WinGate configuration."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.wingate.com/'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/01/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:qbik:wingate");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/telnet", 23);
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

port = get_kb_item("Services/telnet");
if(!port) port = 23;

if(get_port_state(port))soc = open_sock_tcp(port);
else exit(0);
if(soc)
{
buffer = recv(socket:soc, length:1);
n = strlen(buffer);
if(n == 0)exit(0);

buffer = recv(socket:soc, length:7);
if(!buffer){
		close(soc);
		exit(0);
 	  }
b = string("localhost\r\n");
send(socket:soc, data:b);
r = recv(socket:soc, length:1024);
if(!r){
	close(soc);
	exit(0);
	}
r = tolower(r);
for(i=0;i<11;i=i+1){
		d = recv(socket:soc, length:1);
		if(!d){
			close(soc);
			exit(0);
			}
		}
r = recv(socket:soc, length:100);
r = tolower(r);
if(("connecting to host" >< r)){
	security_hole(port);
	set_kb_item(name:"wingate/enabled", value:TRUE);
	}
close(soc);
}
