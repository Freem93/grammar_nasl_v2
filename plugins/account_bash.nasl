#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
account = "bash";

if (description)
{
  script_id(15583);
  script_version ("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/09/25 13:39:52 $");

  script_cve_id("CVE-1999-0502");
  script_osvdb_id(822);
 
  script_name(english:"Unpassworded 'bash' Backdoor Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an account with a blank password.");
  script_set_attribute(attribute:"description", value:
"The account 'bash' has no password set. An attacker may use it to gain 
further privileges on this system. 

This account was likely created by a backdoor installed by a fake Linux 
RedHat patch.");
 # http://web.archive.org/web/20050221110541/http://packetstormsecurity.nl/0410-advisories/FakeRedhatPatchAnalysis.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?231c3c89");

  script_set_attribute(attribute:"solution", value:"Disable this account and check your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 
  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}
include("audit.inc");
include("default_account.inc");
include('global_settings.inc');

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:account);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
