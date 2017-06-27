#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22482);
  script_version("$Revision: 1.15 $");

  script_name(english:"Do not scan Novell NetWare");
  script_summary(english:"Marks Novell NetWare systems as dead");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running Novell NetWare and will not be
scanned." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Novell NetWare.  This operating
system has a history of crashing or otherwise being adversely affected
by scans.  As a result, the scan has been disabled against this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08f07636" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87d03f4c" );
 script_set_attribute(attribute:"solution", value:
"If you want to scan the remote host enable the option 'Scan Novell
NetWare hosts' in the Nessus client and re-scan it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/02");
 script_cvs_date("$Date: 2012/09/10 20:11:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_SETTINGS);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");
  script_dependencies("dont_scan_settings.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("snmp_func.inc");

if (  get_kb_item("Scan/Do_Scan_Novell") ) exit(0);



# Check SNMP.
if (get_kb_item("SNMP/community"))
{
  port = get_kb_item("SNMP/port"); 
  community = get_kb_item("SNMP/community");
  if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
  soc = open_sock_udp(port);
  if (soc) 
  {
    desc = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.23.1.6");
    close(soc);
    if (desc && "Novell NetWare" >< desc)
    {
      set_kb_item(name:"Host/Netware", value:TRUE);
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0, extra:'\nSNMP reports the host as running Novell NetWare.\n');
      exit(0);
    }
  }
}



# Check web servers.
foreach port (make_list(81, 8009))
{
  if (get_port_state(port))
  {
    r = http_send_recv3(port:port, item: "/", version: 10, method:"GET");
    if (isnull(r)) continue;
    banner = strcat(r[0], r[1], '\r\n', r[2]);
    # nb: don't save banners from an HTTP 1.0 request as they may 
    #     cause problems for scans of name-based virtual hosts.
    # set_kb_item(name: 'www/banner/'+port, value: banner);
    if ("Server: NetWare HTTP Stack" >< r[1])
    {
      set_kb_item(name:"Host/Netware", value:TRUE);
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0, extra:'\nThe web server on port ' + port + ' uses a Server response header that suggests\nit runs under NetWare.\n');
      exit(0);
    }
  }
}

foreach port (make_list(80))
{
  if (get_port_state(port))
  {
    r = http_send_recv3(method:"GET", port:port, item:"/", version: 10);
    if (isnull(r)) continue;
    banner = strcat(r[0], r[1], '\r\n', r[2]);
    # nb: don't save banners from an HTTP 1.0 request as they may 
    #     cause problems for scans of name-based virtual hosts.
    # set_kb_item(name: 'www/banner/'+port, value: banner);
    if (
      "(NETWARE)" >< banner &&
      egrep(pattern:"^Server: Apache(/[^ ]*)? \(NETWARE\)", string:r[1])
    )
    {
      set_kb_item(name:"Host/Netware", value:TRUE);
      set_kb_item(name:"Host/dead", value:TRUE);
      security_note(port:0, extra:'\nThe web server on port ' + port + ' uses a Server response header that suggests\nit runs under NetWare.\n');
      exit(0);
    }
  }
}
