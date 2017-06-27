#
# This script was written by Keith Young
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, family change (8/15/09)


include("compat.inc");

if(description)
{
 script_id(11642);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2003-0725");
 script_bugtraq_id(8476);
 script_osvdb_id(11772);
 
 script_name(english:"Helix Servers View Source Plug-in RTSP Parser Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote media streaming server is susceptible to buffer overflow
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RealServer or Helix Universal Server, media
streaming servers. 

According to its banner, the version of the server installed on the
remote host may be affected by a buffer overflow vulnerability when
handling URLs with many '/' characters and another when handling
unspecified RTSP methods.  Using a specially crafted request, an
attacker may be able to leverage either of these issues to execute
arbitrary code subject to the privileges of the user under which the
server operates, generally root or Administrator." );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/bufferoverrun030303.html" );
 # http://web.archive.org/web/20031005094136/http://lists.immunitysec.com/pipermail/dailydave/2003-August/000030.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d552d421" );
 script_set_attribute(attribute:"see_also", value:"http://www.service.real.com/help/faq/security/rootexploit082203.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.service.real.com/help/faq/security/rootexploit091103.html" );
 script_set_attribute(attribute:"solution", value:
"Install the Helix Universal Server 9.01 Security Update or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/08/22");
 script_cvs_date("$Date: 2013/06/03 21:40:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"RealServer and Helix Server Overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Montgomery County Maryland Government Security Team");
 script_family(english:"Gain a shell remotely");
 script_dependencie("rtsp_detect.nasl");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}

#
# Open the connection on port 554 and send the OPTIONS string
#

 port = get_kb_item("Services/rtsp");
 if(!port)port = 554;
 if (get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   data = string("OPTIONS * RTSP/1.0\r\n\r\n");
   send(socket:soc, data:data);
   header = recv(socket:soc, length:1024);
   if(("RTSP/1" >< header) && ("Server:" >< header)) {
     server = egrep(pattern:"Server:",string:header);

# Currently, all versions up to and including 9.0.1 are affected

     if( (egrep(pattern:"Version [0-8]\.[0-9]", string:server)) ||
         (egrep(pattern:"Version 9\.0\.[0-1]", string:server)) ) {
      security_hole(port);
     }
   }
  close(soc);
  }
 }
