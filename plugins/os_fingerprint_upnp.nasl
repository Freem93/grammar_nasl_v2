#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52043);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/26 23:55:56 $");

  script_name(english:"OS Identification : UPnP");
  script_summary(english:"Identifies devices based on UPnP data.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the remote operating system by querying a
UPnP service.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote operating system by querying
its UPnP web server using SOAP.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("upnp_www_server.nasl");
  script_require_keys("upnp/www");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

global_var conf, name, type;

port = get_kb_item_or_exit("upnp/www");
dt = get_kb_item_or_exit("upnp/" + port + "/deviceType");
type = "embedded";
if (':device:InternetGatewayDevice:' >< dt) type = 'router';

manufacturer = get_kb_item("upnp/" + port + "/manufacturer");
modelNumber = get_kb_item("upnp/" + port + "/modelNumber");
modelName = get_kb_item("upnp/" + port + "/modelName");
fName = get_kb_item("upnp/" + port + "/friendlyName");
if (fName)
{
  if ("Cisco" >< manufacturer || "Linksys" >< manufacturer)
  {
    foreach n (make_list("WET610N"))
      if (fName == n)
      {
        set_kb_item(name:"Host/OS/UPnP", value: "Linksys Wireless Access Point - "+n);
        set_kb_item(name:"Host/OS/UPnP/Confidence", value: 100);
        set_kb_item(name:"Host/OS/UPnP/Type", value: "wireless-access-point");
        exit(0);
      }
  }

  if ("Netgear " >< fName)
  {
    foreach n (make_list(
      "CGD24N", "CGD24G", "CGE24N", "CG2000", "CG2100", "CG3000", "CG3100",
      "CBVG834G", "CG3200", "CG3300"))
      if (fName == "Netgear "+n)
      {
        set_kb_item(name:"Host/OS/UPnP", value: "Netgear Cable Router");
        set_kb_item(name:"Host/OS/UPnP/Confidence", value: 100);
        set_kb_item(name:"Host/OS/UPnP/Type", value: "wireless-access-point");
        exit(0);
      }

    foreach n (make_list(
      "WNDAP350", "WNAP210", "WG302", "WG103", "WG102", "WN802T", "WAG102",
      "WNEB3100" ))
      if (fName == "Netgear "+n)
      {
        set_kb_item(name:"Host/OS/UPnP", value: "Netgear Wireless Router");
        set_kb_item(name:"Host/OS/UPnP/Confidence", value: 100);
        set_kb_item(name:"Host/OS/UPnP/Type", value: "wireless-access-point");
        exit(0);
      }
  }

  if ("ARCHOS" >< manufacturer || "Archos" >< modelName)
  {
    if ("Archos70" >< modelName)
    {
      v = eregmatch(string: modelNumber, pattern: '([0-9]+\\.[0-9]+\\.[0-9]+)( |$)');
      if (isnull(v)) a = "Android";
      else a = "Android "+v[1];
      set_kb_item(name:"Host/OS/UPnP", value: "Linux Kernel on " + a + " (" + modelName + ")");
      set_kb_item(name:"Host/OS/UPnP/Confidence", value: 100);
      set_kb_item(name:"Host/OS/UPnP/Type", value: "mobile");
      exit(0);
    }
  }

  if (name == "Linux Internet Gateway Device")
  {
    # Not very useful: no kernel version, no distro => low confidence
    set_kb_item(name:"Host/OS/UPnP", value: "Linux");
    set_kb_item(name:"Host/OS/UPnP/Confidence", value: 20);
    set_kb_item(name:"Host/OS/UPnP/Type", value: "general-purpose");
    exit(0);
  }

  if ("Sonos" >< fName)
  {
    set_kb_item(name:"Host/OS/UPnP", value: "Linux (" + modelName + ")");
    set_kb_item(name:"Host/OS/UPnP/Confidence", value: 70);
    set_kb_item(name:"Host/OS/UPnP/Type", value: "embedded");
    exit(0);
  }


}

mDescr = get_kb_item("upnp/modelDescription");
if (mDescr)
{
  if (mDescr == "HDHomeRun Network Tuner")
  {
    set_kb_item(name:"Host/OS/UPnP", value: "HDHomeRun Networked Digital TV Tuner");
    set_kb_item(name:"Host/OS/UPnP/Confidence", value: 90);
    set_kb_item(name:"Host/OS/UPnP/Type", value: "embedded");
    exit(0);
  }
}

modelName = get_kb_item("upnp/modelName");
modelNumber = get_kb_item("upnp/modelNumber");
if ("Windows Media Player Sharing" >< modelName)
{
  if (modelNumber)
  {
    # http://en.wikipedia.org/wiki/Windows_Media_Player
    if (modelNumber =~ "^12\.") os = 'Microsoft Windows 7\nMicrosoft Windows 2008 R2';
    else if (modelNumber =~ "^11\.") os = 'Microsoft Windows Server 2008\nMicrosoft Windows Vista\nMicrosoft Windows XP';
    else if (modelNumber =~ "^10\.") os = 'Microsoft Windows Server 2003\nMicrosoft Windows XP';
    else if (modelNumber =~ "^9\.") os = 'Microsoft Windows XP\nMicrosoft Windows 2000\nMicrosoft Windows ME\nMicrosoft Windows 98';
    else if (modelNumber =~ "^8\.") os = 'Microsoft Windows XP';
    else if (modelNumber =~ "^7\.1($|[^0-9])") os = 'Microsoft Windows 2000\nMicrosoft Windows ME\nMicrosoft Windows 98';
    else if (modelNumber =~ "^7\.0($|[^0-9])") os = 'Microsoft Windows 2000\nMicrosoft Windows ME\nMicrosoft Windows 98\nMicrosoft Windows NT 4.0\nMicrosoft Windows 95';
    else if (modelNumber =~ "^6\.4($|[^0-9])") os = 'Microsoft Windows XP\nMicrosoft Windows 2000\nMicrosoft Windows ME\nMicrosoft Windows 98\nMicrosoft Windows NT 4.0\nMicrosoft Windows 95';
    else if (modelNumber =~ "^6\.1($|[^0-9])") os = 'Microsoft Windows 98\nMicrosoft Windows 95';
  }
  if (!os) os = "Microsoft Windows";

  set_kb_item(name:"Host/OS/UPnP", value:os);
  set_kb_item(name:"Host/OS/UPnP/Confidence", value:70);
  set_kb_item(name:"Host/OS/UPnP/Type", value: "general-purpose");
  exit(0);
}
else if ("Roku Streaming Player 3500X" >< modelName)
{
  os = "Roku 3500 Streaming Stick";

  set_kb_item(name:"Host/OS/UPnP", value:os);
  set_kb_item(name:"Host/OS/UPnP/Confidence", value:85);
  set_kb_item(name:"Host/OS/UPnP/Type", value: "embedded");
  exit(0);
}


exit(0, "Nessus was not able to identify the OS from the UPnP service.");
