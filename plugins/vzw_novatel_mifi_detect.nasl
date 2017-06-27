#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50513);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/09/14 19:48:34 $");

  script_name(english:"Novatel MiFi Detection");
  script_summary(english:"Detects a MiFi Device");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a MiFi device.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Novatel MiFi device, a portable access point
using 3G/EVDO to connect to the Internet.");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of such devices is in line with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports(80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

res = http_get_cache(item:"/", port:80, exit_on_fail:TRUE);

if ("<title>Administration</title>" >< res &&
    '<meta name="description" content="VZ020">' >< res &&
    'Verizon MiFi2200 E734' >< res )
{
 set_kb_item(name:"Host/novatel_mifi_device", value:TRUE);
 res =  http_send_recv3(port:80, item:"/getStatus.cgi?dataType=TEXT", method:"GET", exit_on_fail: 1);    # Extract the public IP of this device
 if ( res[2] =~ "IpAddr=([0-9.]+)" ) 
  IpAddr = ereg_replace(pattern:".*WwIpAddr=([0-9.]+).*", string:res[2], replace:"\1");
 if ( IpAddr )
  security_note(port:80, extra:'The public IP address of this device is ' + IpAddr);
 else
  security_note(80);
}
