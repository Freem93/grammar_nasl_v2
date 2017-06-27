#
# (C) Tenable Network Security, Inc.
#

account = "root";
password = "dasdec1";

include("compat.inc");

if (description)
{
  script_id(68959);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/25 13:39:53 $");

  script_cve_id("CVE-1999-0502", "CVE-2013-4735");
  script_bugtraq_id(60915);
  script_osvdb_id(90379);

  script_name(english:"Default password (dasdec1) for 'root' account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:"An account on the remote host uses a known password.");
  script_set_attribute(
    attribute:"description",
    value:
"The account 'root' on the remote host has the password 'dasdec1'.  An
attacker may leverage this issue to gain access to the affected system
and launch further attacks against it."
  );
  # http://www.usatoday.com/story/news/nation/2013/02/13/police-believe-zombie-hoax-attacks-linked/1915921/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d23daf7");
  script_set_attribute(attribute:"solution", value:"Change the device's root password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");

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

if (!thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
  exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = check_account(login:account, password:password);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
