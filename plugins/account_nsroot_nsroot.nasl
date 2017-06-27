#
# (C) Tenable Network Security, Inc.
#


account = "nsroot";
password = "nsroot";


include("compat.inc");


if (description)
{
  script_id(66393);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_cve_id("CVE-1999-0502");

  script_name(english:"Default Password (nsroot) for 'nsroot' Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote system can be accessed with a default account."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The account 'nsroot' on the remote host has the password 'nsroot'.

An attacker may leverage this issue to gain administrative access to 
the affected system. 

Note that Citrix NetScaler appliances are known to use these 
credentials to provide complete, administrative access to the Citrix 
NetScaler appliance."
  );
  # http://support.citrix.com/proddocs/topic/netscaler-admin-guide-93/ns-ag-aa-reset-default-amin-pass-tsk.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74336bf9");
  script_set_attribute(
    attribute:"solution", 
    value:
"If the host is a Citrix NetScaler, reset the nsroot password. 

Otherwise, set a strong password for this account or use ACLs to
restrict access to the host."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (!thorough_tests && !get_kb_item("Settings/test_all_accounts")) exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:account, password:password, unix:FALSE);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
