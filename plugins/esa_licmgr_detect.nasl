#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22128);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/31 21:45:42 $");

  script_name(english:"eIQnetworks Enterprise Security Analyzer License Manager Detection");
  script_summary(english:"Detects an eIQnetworks Enterprise Security Analyzer License Manager");

 script_set_attribute(attribute:"synopsis", value:
"A license manager is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a license manager for eIQnetworks
Enterprise Security Analyzer (ESA), a security information and event
management application. 

Note that eIQnetworks Enterprise Security Analyzer is also included in
third-party products such as Astaro Report Manager, Fortinet
FortiReporter, and iPolicy Security Reporter." );
 # http://web.archive.org/web/20070713115713/http://www.eiqnetworks.com/products/EnterpriseSecurityAnalyzer.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b298df0f" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 10616);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(10616);
  if (!port) exit(0);
}
else port = 10616;
if (!get_tcp_port_state(port)) exit(0);


# Make sure it looks like the license manager.
soc = open_sock_tcp(port);
if (!soc) exit(0);

send(socket:soc, data:"LICMGR_ISLICENSE");
res = recv(socket:soc, length:64);
if ("Error!" >!< res) exit(0);
close(soc);


# Try to get some interesting information.
cmds = make_list(
  "LICMGR_GETNICADDRESS",
  "LICMGR_CHECKNUMBEROFLICENSES",
  "LICMGR_GETLICENSES",
  "QUERYSYSTEMINFO&127.0.0.1"
);
info = "";
foreach cmd (cmds)
{
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  send(socket:soc, data:cmd);
  res = recv(socket:soc, length:256);
  close(soc);

  if (res)
  {
    if ("CHECKNUMBEROFLICENSES" >< cmd) info += 'Number of licenses : ' + res + '\n';
    else if ("GETLICENSES" >< cmd)      info += 'License Info       : ' + res + '\n';
    else if ("GETNICADDRESS" >< cmd)
    {
      res = ereg_replace(pattern:"(..)", replace:"\1:", string:res);
      res = str_replace(find:":|", replace:" ", string:res);
      info += 'NIC Address        : ' + res + '\n';
    }
    else if ("QUERYSYSTEMINFO" >< cmd)
    {
      ver = strstr(res, "Build=");
      if (ver)
      {
        ver = ver - strstr(ver, '~');
        ver = ver - "Build=";
      }
      res = str_replace(find:"~", replace:'\n                     ', string:res);
      info += 'System Info        : ' + res + '\n';
    }
  }
}


# If we got some info from the remote host...
if (info)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"esa_licmgr");
  if (ver) set_kb_item(name:"ESA/Licmgr/"+port+"/Version", value:ver);

  security_note(port:port, extra: info);
}
