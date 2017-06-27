#
# (C) Tenable Network Security, Inc.
#


account = "root";
password = "abc123";


include("compat.inc");


if (description)
{
  script_id(65820);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/27 14:49:38 $");

  script_cve_id("CVE-1999-0502");

  script_name(english:"Default Password (abc123) for 'root' Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote system can be accessed with a default password."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The account 'root' on the remote host has the password 'abc123'. 

An attacker may leverage this issue to gain full access to the affected
system. 

Note that Junos Space is known to use these credentials by default."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=KB26220");
  script_set_attribute(attribute:"solution", value:"Set a strong password for this account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:juniper:junos_space");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
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
