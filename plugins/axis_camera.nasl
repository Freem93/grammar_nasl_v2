#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if (description)
{
  script_id(10502);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/10/09 22:45:48 $");

  script_cve_id("CVE-2001-1543");
  script_osvdb_id(401);
  script_xref(name:"Secunia", value:"12353");

 
  script_name(english:"Axis Camera Default Password");
  script_summary(english:"Checks for Axis Network Camera Default Password");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a default password set.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to be an Axis Network Camera. It was possible to
log into the remote host with the default credentials 'root/pass'.

An attacker may use these credentials to trivially access the system.");
  script_set_attribute(attribute:"solution", value:
"Set a strong password for this account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:axis:2100_network_camera");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");

 exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('telnet_func.inc');
include('global_settings.inc');
include('misc_func.inc');

if (!thorough_tests && !get_kb_item("Settings/test_all_accounts")) exit(0, "Neither thorough_tests nor test_all_accounts is set.");

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);

if (soc)
{
  banner = telnet_negotiate(socket:soc);
  req = 'root\r\n';
  send(socket:soc, data:req);
  recv(socket:soc, length:1000);
  req = 'pass\r\n';
  send(socket:soc, data:req);
  r = recv(socket:soc, length:1000);
  if("Root" >< r)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to gain access using the following information :\n' +
        '\n' +
        '  User     : root\n' +
        '  Password : pass\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    close(soc);
    exit(0);
  }
  close(soc);
  audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_SOCK_FAIL, port);

