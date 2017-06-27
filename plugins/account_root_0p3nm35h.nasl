#
# (C) Tenable Network Security, Inc.
#

account = "root";
password = "0p3nm35h";


include("compat.inc");

if (description)
{
  script_id(48274);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_cve_id("CVE-1999-0502");

  script_name(english:"Default Password (0p3nm35h) for 'root' Account");
  script_summary(english:"Attempts to log in to the remote host.");
     
  script_set_attribute(attribute:"synopsis", value:
"An account on the remote host uses a known password.");
  script_set_attribute(attribute:"description", value:
"The account 'root' on the remote host has the password '0p3nm35h'. 
An attacker may leverage this issue to gain total control of the
affected system.

Note that some network devices are known to use these credentials by
default.");
  script_set_attribute(attribute:"solution", value:
"Set a strong password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  # https://web.archive.org/web/20101029225701/http://robin-mesh.wik.is/Howto/Router_Access/SSH_Access
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d0967a9");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencie("ssh_detect.nasl", "account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
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
