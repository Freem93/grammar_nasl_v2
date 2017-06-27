#
# (C) Tenable Network Security, Inc.
#

account = "ucspe";
password = "ucspe";

include("compat.inc");

if (description)
{
  script_id(91959);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/08 14:36:26 $");

  script_osvdb_id(137190);

  script_name(english:"Default Password (ucspe) for 'ucspe' Account");
  script_summary(english:"Attempts to log into the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"The account 'ucspe' on the remote host has the password 'ucspe'. An
attacker can exploit this issue to gain administrative access to the
affected system.

Note that Cisco Unified Computing System Platform Emulator is known to
use these credentials to provide administrative access to the CLI.");
  script_set_attribute(attribute:"solution", value:
"Set a strong password for this account or use ACLs to restrict access
to the host.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system_platform_emulator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (!thorough_tests && !get_kb_item("Settings/test_all_accounts"))
  exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:account, password:password, unix:FALSE);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
