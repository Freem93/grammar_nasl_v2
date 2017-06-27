#
# (C) Tenable Network Security, Inc.
#

account = "root";
password = "xc3511";

include("compat.inc");

if (description)
{
  script_id(94400);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/25 16:29:07 $");

  script_cve_id("CVE-1999-0502", "CVE-2016-1000245");
  script_osvdb_id(145623);

  script_name(english:"Default Password 'xc3511' for 'root' Account");
  script_summary(english:"Attempts to log into the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"An administrative account on the remote host uses a known default
password.");
  script_set_attribute(attribute:"description", value:
"The account 'root' on the remote host has the default password
'xc3511'. A remote attacker can exploit this issue to gain
administrative access to the affected system.");
  script_set_attribute(attribute:"solution", value:
"Change the password or disable the account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:account, password:password);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
