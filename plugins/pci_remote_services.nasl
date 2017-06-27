#TRUSTED 318c8a031f9f5df87ddf62b8cd2b96c9370736eb980a65a2ce67e56a7de64f57ef09bf961983d2536f8b525cb4d6e4b2d07aae24575e068cd2980473586b1ae43204a144b4fde974f753a3bc8d40e24b3552e62a732cd7ba08138f68eecd266cc845b4c00a3accc56a8834352d34f20ce33345809b2a760745a8ef86189879cbfad8b16a70016236d1481368c79d36e49a0b05221a47151ed6fe04dfaf499d11547f94606e3d4fdda5bad2458ffdf8207f915d0a2cf5d830517db5c8e749af317cca5ff693936a744a530099bc2a6fdd3b90f8c15d9b40ace4d5d225ece6831e1f4b5cff4a0c1b7eb35513deac4ab12138837012ac47256fba36005b5f618511cd700c0c8d02c978d70f3e54e9ab0e39cba5e80c952da9a4d581c0ce52e9aed098ee45b5612d8e17a2efc45ac9f6210560c978bf142a90d4c6fea784fac8873331dca672db2b8bae1208b146dd06e1adfe18a4ad82778ea3c52c580f1a22c1523c7440b471edd76c4fe85d57e6f3b0b5f7a88c76f23690937c0cff8f49241f6e4191a2c9efa8d5d1e723645f017fb7c6488ed09378772bc0fc5cfb45035981a0575b4c8828dfbb83b01ae4cdb2aa403f9c6b140ac732c76ef6a4b0c015b8b04514f2825ddad6c3c3593af22139939bb1551342db0ba813b6a7cbbaae137bb5a6356928e3c18bceef3748aee029399b8db929387e40a9a3d397d3c598a603e0bf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56209);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/17");

 script_name(english:"PCI DSS Compliance : Remote Access Software Has Been Detected");
 script_summary(english:"Modify global variables for PCI DSS.");

 script_set_attribute(attribute:"synopsis", value:
"Remote access software has been detected.");
 script_set_attribute(attribute:"description", value:
"Due to increased risk to the cardholder data environment when remote
access software is present, please 1) justify the business need for
this software to the ASV and 2) confirm it is either implemented
securely per Appendix D in the ASV Program Guide, or disabled /
removed. Please consult your ASV if you have questions about this
Special Note.");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/15");

 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_set_attribute(attribute:"risk_factor", value:"Medium");

 script_end_attributes();

 script_category(ACT_END);

 script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
 script_family(english:"Policy Compliance");

 script_require_keys("Settings/PCI_DSS");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

function pci_webapp_chk(port, app)
{
  if (isnull(app) || isnull(port)) return NULL;
  local_var install, chk_app, dir, urls;

  urls = make_list();
  chk_app = get_installs(
    app_name : app,
    port     : port
  );
  if (chk_app[0] == IF_OK)
  {
    foreach install (chk_app[1])
    {
      dir = install['path'];
      urls = make_list(urls, build_url2(qs:dir, port:port));
    }
    return urls;
  }
  else
    return NULL;
}

str = NULL;

ports = get_kb_list("Services/www");

if ( ! isnull(ports) )
{
 foreach port ( make_list(ports) )
 {
   page = get_kb_item("Cache/" + port + "/URL_/");
   # Cisco
   if ( page && 'WWW-Authenticate: Basic realm="level_15' >< page )
    {
      str += '\nA web-based Cisco management interface is running on the remote host on TCP port ' +  port + '.\n';
    }

   # Citrix Access Gateway Administrative Web Interface
   app = 'citrix_access_gateway_admin';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nCitrix Access Gateway Administrative Web Interface, a web-based management application for Citrix Access Gateway, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # Cobbler Admin Interface
   app = 'cobbler_web_admin';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nA web-based administration interface for Cobbler, a Linux distribution, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # CodeMeter
   app = 'CodeMeter';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nCodeMeter WebAdmin, a web-based management application for CodeMeter hardware and software, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # HP Guardian Service Processor
   if (
     page &&
     '<TITLE>HP Web Console on' >< page &&
     '<APPLET CODE="pericom/TeemWorld/TeemWorld.class" ARCHIVE="TeemWorld.jar" ' >< page &&
     '<PARAM NAME=IPAddress' >< page
   )
   {
    str += '\nAn HP Guardian Service Processor interface is running on the remote host on TCP port ' +  port + '.\n';
   }

   # HP iLO
   if (
     page &&
     'Hewlett-Packard Development Company, L.P.' >< page &&
     (
       '<title>iLO 4</title>' >< page ||
       'id="titleHeading">iLO&nbsp;4</h1>' >< page ||
       '<title>iLO 3</title>' >< page ||
       'id="titleHeading">Integrated&nbsp;Lights-Out&nbsp;3</h1>' >< page ||
       '<TITLE>HP Integrated Lights-Out ' >< page
     )
   )
   {
    str += '\nAn HP Integrated Lights-Out (iLO) interface is running on the remote host on TCP port ' +  port + '.\n';
   }

   # HP Web Jetadmin
   app = 'hp_web_jetadmin';
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nHP Web Jetadmin, a web-based management application for networked printers, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   if ( page && '<form METHOD="POST" NAME="form" ACTION="/cgi-bin/home.tcl">' >< page &&
	        '<b>Acquire Exclusive Configuration Lock</b>' >< page )
   {
    str += '\nA web-based management interface is running on the remote host on TCP port ' + port + '.\n';
   }

   # MongoDB Web Admin Interface
   app = "mongodb_web";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nMongoDB Web Admin Interface, a web-based MongoDB database management interface, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # OpenAdmin Tool
   app = "openadmin_tool";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nOpenAdmin Tool, a web-based tool for managing Informix database servers, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # phpLDAPadmin
   app = "phpLDAPadmin";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nphpLDAPadmin, a web-based LDAP management client, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # phpMoAdmin
   app = "phpMoAdmin";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nphpMoAdmin, a web-based MongoDB database management interface, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

   # phpMyAdmin
   app = "phpMyAdmin";
   urls = pci_webapp_chk(app:app, port:port);
   if (!isnull(urls))
   {
     if ( max_index(urls) == 1) location = 'location';
     else location = 'locations';
     str += '\nphpMyAdmin, a web-based MySQL database management interface, is running on the remote host at the following ' +location + ' :\n';
     foreach url (urls)
     {
       str += '\n  '+url;
     }
     str += '\n';
   }

 }
}

# HP Onboard Administrator
hp_ports = get_kb_list('Host/HP/Onboard_Administrator/Port');
if (!isnull(hp_ports))
{
  foreach hp_port (hp_ports)
  {
    str += '\nAn HP Onboard Administrator interface is running on the remote host on TCP port ' + hp_port + '.\n';
  }
}

services = make_array(
  "ard",            "An Apple Remote Desktop server (remote administration)",
  "ca_rchost",      "A Unicenter Remote Control agent (remote administration)",
  "cifs",           "A CIFS server",
  "cisco-ssl-vpn-svr", "A Cisco ASA SSL VPN server (VPN)",
  "dameware",       "A DameWare server (remote administration)",
  "db2das",         "An IBM DB2 Administration Server",
  "db2das_connect", "An IBM DB2 Administration Server",
  "domino_console", "A Lotus Domino console",
  "ebsadmin",       "A McAfee E-Business Server (remote administration)",
  "egosecure_endpoint", "An EgoSecure EndPoint remote administration service",
  "hydra_saniq",    "An HP LeftHand OSremote administration",
  "ikev1",          "An IKEv1 server (VPN)",
  "ikev2",          "An IKEv2 server (VPN)",
  "inoweb",         "A Computer Associates administration server",
  "juniper_nsm_gui_svr", "A Juniper NSM GUI Server (remote administration)",
  "l2tp",           "An L2TP server (VPN)",
  "lgserver_admin", "An ARCserve Backup server",
  "linuxconf",      "A LinuxConf server (remote administration)",
  "mikrotik_mac_telnet", "A MikroTik MAC Telnet Protocol (remote administration)",
  "msrdp",          "A Terminal Services server (remote display)",
  "netbus",         "A NetBus remote administration tool",
  "netbus2",        "A NetBus remote administration tool",
  "openvpn",        "An OpenVPN server (VPN)",
  "pcanywhereaccessserver", "A Symantec pcAnywhere Access server (remote administration)",
  "pcanywheredata", "A pcAnywhere server (remote administration)",
  "pptp",           "A PPTP server (VPN)",
  "radmin",         "An Radmin server (remote administration)",
  "remote_pc",      "A Remote PC Access server (remote administration)",
  "rlogin",         "An rlogin server (remote terminal)",
  "rsh",            "An rsh server (remote terminal)",
  "smb",            "An SMB server",
  "ssh",            "An SSH server (remote terminal)",
  "synergy",        "A Synergy server (remote administration)",
  "teamviewer",     "A TeamViewer server (remote administration)",
  "telnet",         "A Telnet server (remote terminal)",
  "tinc_vpn",       "A Tinc VPN server (VPN)",
  "tor",            "A Tor relay (VPN)",
  "ultravnc-dsm",   "An UltraVNC server (remote display)",
  "veritas-ucl",    "A Symantec Veritas Enterprise Administrator Service",
  "vnc",            "A VNC server (remote display)",
  "vncviewer",      "A VNC Viewer listener (remote display)",
  "www/hp_smh",     "An HP System Management Homepage server (remote administration)",
  "www/logmein",    "A LogMeIn server (remote administration)",
  "www/webmin",     "A webmin server (remote administration)",
  "x11",            "An X11 server (remote display)"
);

foreach service (keys(services))
{
  desc = services[service];
  protos = make_array();
  ipprotos = make_list("TCP", "UDP");

  # Get TCP/UDP port(s) for each service
  foreach ipproto (ipprotos)
  {
    kb = NULL;
    if (ipproto == "TCP")      kb = "Services/" + service;
    else if (ipproto == "UDP") kb = "Services/udp/" + service;

    ports = get_kb_list(kb);
    if (empty_or_null(ports)) continue;

    ports = make_list(ports);
    protos[service][ipproto] = ports;
  }

  if (empty_or_null(protos)) continue;

  # Add to report
  foreach svc (keys(protos))
  {
    foreach proto (keys(protos[svc]))
    {
      ports = protos[svc][proto];
      index = max_index(ports);
      s = 's';
      sep = '';

      # Determine if 'and' or ', and' should be used
      if (index == 1) s = NULL;
      else if (index == 2) sep = ' and ';
      else if (index > 2)
      {
        ports[index-1] = 'and ' + ports[index-1];
        sep = ', ';
      }

      ports = join(ports, sep:sep);

      # E.g. An SSH server (remote terminal) is running on the remote host on TCP port 22.
      str += '\n'+desc+' is running on the remote host on '+proto+' port'+s+' '+ports+'.\n';
    }
  }
}

if (strlen(str) > 0)
{
  security_warning(extra:str, port:0);
}
