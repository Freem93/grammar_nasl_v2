#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10646);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2017/05/16 19:43:12 $");

 script_name(english:"Lion Worm Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a suspicious application installed." );
 script_set_attribute(attribute:"description", value:
"This host seems to be infected by the lion worm, because it has root 
shells running on extra ports and a copy of SSH running on port 
33568." );
 # http://web.archive.org/web/20130415165037/http://antivirus.about.com/library/virusinfo/bllion.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a812683" );
 script_set_attribute(attribute:"solution", value:
"Remove the application or re-install this system from scratch" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


 script_set_attribute(attribute:"plugin_publication_date", value: "2001/04/05");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines the presence of Lion");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2017 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_require_ports(60008, 33567, 33568);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

function check_shell(port)
{
 local_var r, soc;
 soc = open_sock_tcp(port);
 if(!soc)return(0);
 #r = recv(socket:soc, length:4096);
 r = string("id\r\n");
 send(socket:soc, data:r);
 r = recv(socket:soc, length:4096);
 close(soc);
 if("command not found" >< r){
 	security_hole(port);
	return(1);
	}
  if("uid=" >< r){
  	security_hole(port);
	return(1);
	}
 return(0);
}

if(get_port_state(60008))
{
 if(check_shell(port:60008))
  exit(0);
}

if(get_port_state(33567))
{
 if(check_shell(port:33567))
  exit(0);
}

if(get_port_state(33568))
{
 soc = open_sock_tcp(33568);
 if(soc)
 {
  r = recv(socket:soc, length:4096);
  close(soc);
  if(r)
  {
   if("SSH-" >< r)security_hole(33568);
   exit(0);
  }
 }
}
