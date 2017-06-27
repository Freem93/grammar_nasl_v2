#
# (C) Tenable Network Security, Inc.
#

account = "admin";
password = "7ujMko0admin";

include("compat.inc");

if (description)
{
  script_id(94367);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_cve_id("CVE-1999-0502");

  script_name(english:"Default Password '7ujMko0admin' for 'admin' Account");
  script_summary(english:"Attempts to log into the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default administrator
account.");
  script_set_attribute(attribute:"description", value:
"The account 'admin' on the remote host has the default password
'7ujMko0admin'. A remote attacker can exploit this issue to gain
administrative access to the affected system.");
  script_set_attribute(
    attribute:"solution",
    value:"Change the password for this account or disable it."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
