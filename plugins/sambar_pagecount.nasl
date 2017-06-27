#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/2/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(10711);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2001-1010");
 script_bugtraq_id(3091, 3092);
 script_osvdb_id(589);

 script_name(english:"Sambar Server pagecount CGI Traversal Arbitrary File Overwrite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow arbitrary
file overwrite." );
 script_set_attribute(attribute:"description", value:
"By default, there is a pagecount script with Sambar Web Server
located at http://sambarserver/session/pagecount
This counter writes its temporary files in c:\sambardirectory\tmp.
It allows to overwrite any files on the filesystem since the 'page'
parameter is not checked against '../../' attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/199410" );
 script_set_attribute(attribute:"solution", value:
"Remove this script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/07/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/21");
 script_cvs_date("$Date: 2011/03/11 21:52:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Make a request like http://www.example.com/session/pagecount";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2011 Vincent Renardias");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:"/session/pagecount", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  if( ("Server: SAMBAR" >< data) && !ereg(string:data, pattern:"^404"))
  {
   security_warning(port);
  }
 }
}
