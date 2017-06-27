#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20301);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2012/08/10 21:36:56 $");
 
  script_name(english:"VMware ESX/GSX Server detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running VMware Server, ESX Server, or
GSX Server." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running a
VMware server authentication daemon, which likely indicates the remote
host is running VMware Server, ESX Server, or GSX Server." );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_server");
script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:esx_server");
script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:gsx_server");
script_end_attributes();

 
  summary["english"] = "Detect VMware Server Authentication Daemon";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
  script_family(english:"Service detection");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/three_digits", 902, "Services/vmware_auth");
  exit(0);
}

#the code
include("global_settings.inc");
include("misc_func.inc");

register = 0;
port = get_kb_item("Services/vmware_auth");
if ( ! port )
{
 register++;
 if (thorough_tests) {
  port = get_3digits_svc(902);
  if ( ! port ) exit(0);
 }
 else port = 902;
}
if (!get_tcp_port_state(port)) exit(0);


banner = get_unknown_banner(port: port, dontfetch:0);
if (banner) {
  #220 VMware Authentication Daemon Version 1.00
  #220 VMware Authentication Daemon Version 1.10: SSL Required
  #220 VMware Authentication Daemon Version 1.10: SSL Required, MKSDisplayProtocol:VNC 
  if ("VMware Authentication Daemon Version" >< banner) {
    if ( register ) register_service(port:port, ipproto:"tcp", proto:"vmware_auth");

    security_note(port);
  }
}
