#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71095);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/09 22:45:48 $");

  script_bugtraq_id(63394);
  script_osvdb_id(99073);

  script_name(english:"ASUS RT-N13U Router Built-in Admin Telnet Account with Unchangeable Password");
  script_summary(english:"Tries to log into device using known credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a telnet service running that accepts known,
built-in credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a telnet service with an unchangeable admin
account with known credentials (admin/admin).  An attacker could log
into this account and gain complete control of the device."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Oct/271");
  script_set_attribute(
    attribute:"solution",
    value:
"There is currently no available fix.  As a workaround, restrict access
to the telnet service."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:asus:rt_n13u");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include("audit.inc");
include("default_account.inc");
include('global_settings.inc');
include('misc_func.inc');


if (!thorough_tests && !get_kb_item("Settings/test_all_accounts")) exit(0, "Neither thorough_tests nor test_all_accounts is set.");

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

banner = get_telnet_banner(port:port);
if ('RT-N13U' >!< banner) audit(AUDIT_NOT_LISTEN, 'Asus RT-N13U', port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

r = _check_telnet(port:port, login:'admin', password:'admin', cmd:'help', cmd_regex:'(Built-in commands:[^#]+)#', out_regex_group:1);
if (r)
{
  if (report_verbosity > 0) security_hole(port:port, extra:default_account_report(cmd:"help"));
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Asus RT-N13U', port);
