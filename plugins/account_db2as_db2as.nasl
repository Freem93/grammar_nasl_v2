#
# This script was written by Chris Foster
# 
# See the Nessus Scripts License for details
#
# Changes by Tenable
# Add global_settings/supplied_logins_only script_exclude_key (06/2015)
# Add exit() messages for more detailed audits
#


account = "db2as";
password = "db2as";


include("compat.inc");

if (description)
{
  script_id(11864);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2015/09/25 13:39:52 $");

  script_cve_id("CVE-1999-0502", "CVE-2001-0051");
  script_bugtraq_id(2068);
  script_osvdb_id(9484);

  script_name(english:"Default Password (db2as) for 'db2as' Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an account with a default password.");
  script_set_attribute(attribute:"description", value:
"The account 'db2as' has the password 'db2as'. An attacker may use it
to gain further privileges on the system.");
  script_set_attribute(attribute:"solution", value:
"Set a strong password for this account or disable it if possible.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/05");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2003-2015 Chris Foster");

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");
 
  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#
# The script code starts here : 
#
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) exit(0, "Nessus is currently configured to not log in with user accounts not specified in the scan policy.");

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:account, password:password);
if (port) security_hole(port:port, extra:default_account_report());
else exit(0, "The remote host is not affected.");
