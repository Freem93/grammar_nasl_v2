#
# (C) Tenable Network Security, Inc.
#


account = "mg3500";
password = "merlin";


include("compat.inc");


if (description)
{
  script_id(50602);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/15 13:39:08 $");

  script_cve_id("CVE-1999-0502", "CVE-2010-4233");
  script_bugtraq_id(44841);
  script_osvdb_id(69333);

  script_name(english:"Default Password (merlin) for 'mg3500' Account");
  script_summary(english:"Attempts to log in to the remote host.");
     
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote system can be accessed with a default account."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The account 'mg3500' on the remote host has the password 'merlin'. 

An attacker may leverage this issue to gain access to the affected
system. 

Note that some Camtron IP cameras are reported to use these
credentials by default."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2010-006.txt"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2010/Nov/127"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Either set a strong password for this account, disable it, or use
ACLs to restrict access to the host."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
