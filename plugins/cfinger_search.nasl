#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10038);
 script_cve_id("CVE-1999-0259");
 script_osvdb_id(32);
 
 script_version ("$Revision: 1.28 $");
 script_name(english:"cfingerd Wildcard Argument Information Disclosure");
 script_summary(english:"finger .@host feature");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote finger server has an information disclosure vulnerability."
 );
 script_set_attribute( attribute:"description", value:
"The remote host is running 'cfingerd', a finger daemon.

There is a bug in the remote cfinger daemon that allows a remote
attacker to get the lists of the users of this system when issuing
the command :

  finger search.**@victim

This information can be used by a remote attacker to mount further
attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1997/May/160"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1997/May/171"
 );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.  Use another finger daemon,
or disable this service in inetd.conf." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/05/23");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:infodrom:cfingerd");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("search.**\r\n");

  send(socket:soc, data:buf);
  recv_line(socket:soc, length:2048);
  data = recv_line(socket:soc, length:2048);
  minus = "----";
  if(minus >< data)
  {
	for(i=1;i<11;i=i+1){
		data = recv_line(socket:soc, length:2048);
		if(!data)exit(0);
		}
	data = recv_line(socket:soc, length:2048);
	if(data){
  		data_low = tolower(data);
  		if(data_low && ("root" >< data_low)) 
		 {
     		 security_warning(port);
		 set_kb_item(name:"finger/search.**@host", value:TRUE);
		 }
		}
  }
  close(soc);
 }
}
