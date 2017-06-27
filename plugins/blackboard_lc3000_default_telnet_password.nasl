#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71096);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_osvdb_id(99057);

  script_name(english:"Blackboard LC3000 Laundry Reader Default Telnet Password");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote device has a telnet service protected with default
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote device has a telnet service protected by known, default
credentials that allow privileged access to the device."
  );
  script_set_attribute(attribute:"see_also", value:"http://dariusfreamon.wordpress.com/2013/10/28/290/");
  # http://sordoniprojects.com/FTP/4680/RFIs/RFI%20153%20Cut%20Sheets.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59f87215");
  script_set_attribute(attribute:"solution", value:"Change the default password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:blackboard:lc3000");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
if ('Blackboard LC3000' >!< banner) audit(AUDIT_NOT_LISTEN, 'Blackboard LC3000', port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

r = _check_telnet(port:port, password:'IPrdr4U', cmd:'status', cmd_regex:'Status:([^>]*Current Time[^>]*Software Versions[^>]*)Type command', out_regex_group:1);
if (r)
{
  if (report_verbosity > 0) security_hole(port:port, extra:default_account_report(cmd:"status"));
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Blackboard LC30000', port);
