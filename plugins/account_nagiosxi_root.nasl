#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49773);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/25 13:39:53 $");

  script_cve_id("CVE-1999-0502");

  script_name(english:"Default Password (nagiosxi) for 'root' Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host uses default credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to SSH into the remote Nagios XI virtual machine
appliance by providing default credentials.  A remote attacker could
exploit this to gain complete control of the remote host."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Secure the root account with a strong password."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include('global_settings.inc');

user = 'root';
pass = 'nagiosxi';

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:user, password:pass);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
