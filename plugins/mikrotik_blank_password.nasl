#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30213);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 16:49:07 $");

  script_cve_id("CVE-1999-0508");

  script_name(english:"MikroTik RouterOS with Blank Password (telnet check)");
  script_summary(english:"Tries to log in as admin");

  script_set_attribute(attribute:"synopsis", value:"A remote router has no password for its admin account.");
  script_set_attribute(attribute:"description", value:
"The remote host is running MikroTik RouterOS without a password for its
'admin' account.  Anyone can connect to it and gain administrative
access to it.");
  script_set_attribute(attribute:"see_also", value:"http://www.mikrotik.com/documentation.html");
  script_set_attribute(attribute:"solution", value:
"Log in to the device and configure a password using the '/password'
command.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("telnet_func.inc");
include('misc_func.inc');

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

banner = get_telnet_banner(port:port);
if (!banner || "MikroTik" >!< banner) audit(AUDIT_NOT_LISTEN, "MikroTik", port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = "admin";
pass = "";


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

res = telnet_negotiate(socket:soc);
res += recv_until(socket:soc, pattern:"ogin:");
if (!res)
{
  close(soc);
  exit(0);
}
send(socket:soc, data:user+'\r\n');

res = recv_until(socket:soc, pattern:"word:");
if (!res)
{
  close(soc);
  exit(0);
}
send(socket:soc, data:pass+'\r\n');

res = recv_until(socket:soc, pattern:"MikroTik RouterOS");
close(soc);

if (res) security_hole(port);
else audit(AUDIT_HOST_NOT, "affected");
