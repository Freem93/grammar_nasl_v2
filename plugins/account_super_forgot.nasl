#
# (C) Tenable Network Security, Inc.
#

account = "super";
password = "forgot";

include("compat.inc");

if (description)
{
  script_id(17292);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/09/23 20:00:43 $");

  script_cve_id("CVE-1999-0502", "CVE-1999-1420", "CVE-1999-1421");
  script_bugtraq_id(212);
  script_osvdb_id(7967, 10867);
 
  script_name(english:"Default Password (forgot) for 'super' Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote system/switch can be accessed using default credentials
with root level privileges.");
  script_set_attribute(attribute:"description", value:
"The account 'super' on the remote host has the password 'forgot'. An
attacker may use it to gain further privileges on this system.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1998/Jul/183");
  script_set_attribute(attribute:"solution", value:
"Set a password for this account or disable it." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 
  script_dependencie("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

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
