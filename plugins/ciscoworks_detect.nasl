#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(19559);
 script_version("$Revision: 1.10 $");
 
 script_name(english:"CiscoWorks Management Console Detection");
 script_summary(english:"Checks for CiscoWorks");

 script_set_attribute(
   attribute:"synopsis",
   value:"A management interface is running on the remote host."
 );
 script_set_attribute( attribute:"description", value:
"The remote host appears to be running CiscoWorks, a LAN Management
solution, on this port." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/en/US/products/sw/cscowork/ps2425/"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"n/a"
 );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/04");
 script_cvs_date("$Date: 2012/08/08 16:04:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:ciscoworks_lan_management_solution");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");
 
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 1741);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/www");
if ( ! port ) port = 1741;

if(get_port_state(port))
{
  res = http_send_recv3(method:"GET", item:'/login.html', port:port);
  if (isnull(res)) exit(0);

  if("<title>CiscoWorks</title>" >< res[2] )
  {
    security_note(port);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
  }
}
