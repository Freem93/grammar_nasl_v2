#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34217);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/07/13 14:14:41 $");

  script_osvdb_id(48241);

  script_name(english:"Default Password (000000) for 'admin' on WIP5000 IP Phone");
  script_summary(english:"Tests for the WIP5000 default account");

  script_set_attribute(attribute:"synopsis", value:
"The remote IP phone has a default password set for the 'admin' user");
  script_set_attribute(attribute:"description", value:
"The remote host is a WIP5000 VOIP phone.  The remote host has the
default password set for the 'admin' user ('000000'). 

An attacker may connect to it and reconfigure it using this account.");
  script_set_attribute(attribute:"solution", value:
"Connect to this port with a web browser and set a strong password, or
change the password from the handheld device directly.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports(8080);
  exit(0);
}

# The script code starts here

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = 8080;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

banner = get_http_banner(port:port, exit_on_fail: 1);
if ("Server: IP-Phone Solution" >!< banner) exit(0, "The web server listening on port "+port+" does not look like IP-Phone Solution.");

w = http_send_recv3(method:"GET", item:"/index.html", port:port,
  username: "", password: "", exit_on_fail: 1);
res = strcat(w[1], w[2]);

if ( w[0] =~ "^HTTP/.* 401 " &&
    "IP-Phone Solution" >< res )
{
 w = http_send_recv3(method:"GET", item: "/index.html", port:port,
   exit_on_fail: 1,
   username:"admin", password: "000000");

 res = strcat(w[0], w[1], '\r\n', w[2]);
 if (w[0] =~ "^HTTP/.* 200 " && "WirelessIP5000A Web Configuration Tool" >< res)
 {
  security_hole(port);
  exit(0);
 }
}
audit(AUDIT_LISTEN_NOT_VULN, "IP-Phone Solution", port);
