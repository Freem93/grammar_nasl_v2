#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25800);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/06/05 18:59:56 $");

  script_name(english:"NetVault Process Manager Service Detection");
  script_summary(english:"Attempts to detect NetVault Process Manager.");

 script_set_attribute(attribute:"synopsis", value:
"A backup service is listening on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote service is an instance of NetVault Process Manager, part
of Dell NetVault, a cross-platform backup and restore application.

Dell NetVault was formerly known as BakBone NetVault Backup.");
  script_set_attribute(attribute:"see_also", value:"http://software.dell.com/products/netvault-backup/");
  # http://web.archive.org/web/20060212101520/http://www.bakbone.com/products/backup_and_restore/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a53ba1e5" );
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");

  script_set_attribute(attribute:"risk_factor", value:"None");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/28");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:dell:netvault_backup");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:bakbone:netvault");
  
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 20031);

  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(20031);
  if (!port) audit(AUDIT_SVC_KNOWN);
}
else port = 20031;

if (known_service(port:port)) audit(AUDIT_SVC_KNOWN);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED,port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL,port);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# Send a request.
req = raw_string(0x01, 0xcb, 0x22, 0x77, 0xc9) +
    mkdword(0x17) +
      crap(data:"i;", length:0x14) + "s;" + mkbyte(0) + 
    mkdword(0) + 
    mkdword(0xc0) + 
    mkdword(0) +
    mkdword(0) +
    mkdword(0) +
    mkdword(0) +
    mkdword(8) + 
    mkdword(3) + 
    mkdword(3) + 
    mkdword(0) + 
    mkdword(0x0b) +
      crap(data:raw_string(0x90), length:0x0a) +
    crap(data:raw_string(0x00), length:0x66) +
    mkbyte(9) + 
      crap(data:raw_string(0x00), length:8);
req = mkdword(strlen(req)+4) + req;
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

if (
  # the initial dword is the packet length and...
  strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res) &&
  # and it looks like a valid response
  substr(res, 4, 9) == substr(req, 4, 9)
)
{
  # Extract some interesting info for the report.
  info = "";
  nvver = NULL;
  nvbuild = NULL;
  # - machine name.
  len = getdword(blob:res, pos:0x4c);
  if (len > 0 && len < strlen(res))
  {
    cname = substr(res, 0x50, 0x50+len-2);
    info += "    Machine name  : " + cname + '\n';
  }
  # - computer os type.
  i = stridx(res, mkdword(5)+"Type"+'\0');
  if (i > 0)
  {
    i += 17;
    len = getdword(blob:res, pos:i);
    info += "    Computer type : " + substr(res, i+4, i+4+len-2) + '\n';
  }
  # - installation type
  i = stridx(res, mkdword(7)+"Server"+'\0');
  if (i > 0)
  {
    i += 19;
    len = getdword(blob:res, pos:i);
    word = substr(res, i+4, i+4+len-2);
    if (word =~ "true") 
    {
      info += "    Installation  : " + "Server" + '\n';
      set_kb_item(name:"NetVault/"+port+"/Type", value:"Server");
    }
    else if (word =~ "false") 
    {
      info += "    Installation  : " + "Client" + '\n';
      set_kb_item(name:"NetVault/"+port+"/Type", value:"Client");
    }
  }
  # - NetVault version.
  i = stridx(res, mkdword(0x0a)+"NVVersion"+'\0');
  if (i > 0)
  {
    i += 22;
    len = getdword(blob:res, pos:i);
    nvver = substr(res, i+4, i+4+len-2);
  }
  i = stridx(res, mkdword(0x0d)+"NVBuildLevel"+'\0');
  if (i > 0)
  {
    i += 25;
    len = getdword(blob:res, pos:i);
    nvbuild = substr(res, i+4, i+4+len-2);
  }
  if (
    !isnull(nvver) && nvver =~ "^[0-9]+$" &&
    !isnull(nvbuild) && nvbuild =~ "^[0-9]+$"
  )
  {
    # Older versions formated like X0YY: X Major version, YY Minor version 
    if(int(nvver) >= 1000 && int(nvver) <= 9999)
      displayver = nvver[0] + '.' + nvver[2] + nvver[3] + " Build "+nvbuild;
    # Dell bought this after version ~ 9 version system changes to X.Y.Z
    else if(int(nvver) >= 10000 && int(nvver) <= 99999)
      displayver = nvver[0] + nvver[1] + '.' + nvver[3] + "." + nvver[4] + "." + nvbuild;
    # Should not happen, but if it does we don't know what to do for displayver
    else
      audit(AUDIT_SERVICE_VER_FAIL,"NetVault",port);

    set_kb_item(name:"NetVault/"+port+"/NVVersion",      value: nvver);
    set_kb_item(name:"NetVault/"+port+"/NVBuild",        value: nvbuild);
    set_kb_item(name:"NetVault/"+port+"/DisplayVersion", value: displayver);

    info += "    Version       : " + displayver + '\n';
  }

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"nvpmgr");

  if (info)
  {
    report =
      '\n  Nessus was able to gather the following information from the remote' +
      '\n  NetVault Process Manager instance : ' +
      '\n\n' + info + '\n';
  }
  else report = NULL;
  security_note(port:port, extra:report);
}
