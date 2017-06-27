#
# (C) Tenable Network Security, Inc.
#
# Thanks to Xavier HUMBERT <xavier@xavhome.fr.eu.org> for giving
# me a copy of CDK
#


include("compat.inc");


if(description)
{
 script_id(10036);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2015/10/21 20:34:20 $");

 script_name(english:"CDK Backdoor Detection");
 script_summary(english:"Detects the presence of CDK");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A backdoor is running on the remote host."
 );
 script_set_attribute( attribute:"description",  value:
"The remote host appears to be running CDK, a backdoor that can be
used to control your system.  This suggests the host has been
been compromised.

A remote attacker can control the system by connecting to this port
and sending the password 'ypi0ca'." );
 script_set_attribute( attribute:"solution", value:
"Verify that the system has been compromised, and reinstall the
operating system if necessary." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/20");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_require_ports(15858, 79);
 
 exit(0);
}


include('global_settings.inc');


if(get_port_state(15858))
{
 soc = open_sock_tcp(15858);
 if(soc)
 {
  data = string("ypi0ca\r\n");
  send(socket:soc, data:data);
  r = recv(socket:soc, length:1024);
  if("Welcome" >< r)
  {
   security_hole(15858);
  }
  close(soc);
 }
}

if ( report_paranoia < 1 ) exit(0);

if(get_port_state(79))
{
 soc2 = open_sock_tcp(79);
 if(soc2)
 {
  data = string("ypi0ca\r\n");
  send(socket:soc2, data:data);
  r = recv(socket:soc2, length:4);
  if("bash" >< r)
  {
   security_hole(79);
  }
  close(soc2);
 }
}
