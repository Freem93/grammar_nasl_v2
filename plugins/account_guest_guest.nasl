#
# (C) Tenable Network Security, Inc.
#

account = "guest";
password = "guest";


include("compat.inc");

if (description)
{
  script_id(11256);
  script_version ("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_cve_id("CVE-1999-0501", "CVE-1999-0502");
 
  script_name(english:"Default Password (guest) for 'guest' Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an account with a default password set.");
  script_set_attribute(attribute:"description", value:
"The account 'guest' has the password 'guest' set. An attacker may use
this to gain further privileges on this system.");
  script_set_attribute(attribute:"solution", value:
"Set a password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");
 
  script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 
  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

   exit(0);
}

#
# The script code starts here : 
#
include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:account, password:password);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
