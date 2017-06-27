#
# (C) Tenable Network Security, Inc.
#


account = "HPSupport";
password = "badg3r5";


include("compat.inc");


if (description)
{
  script_id(67005);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_cve_id("CVE-1999-0502", "CVE-2013-2342");
  script_bugtraq_id(60819);
  script_osvdb_id(94601);

  script_name(english:"Default Password (badg3r5) for 'HPSupport' Account");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:"The remote system can be accessed with a default account.");
  script_set_attribute(
    attribute:"description",
    value:
"The account 'HPSupport' on the remote host has the password 'badg3r5'. 

An attacker may leverage this issue to gain administrative access to the
affected system.

Note that HP StoreOnce D2D Backup systems running software version
2.2.17 / 1.2.17 or older are known to have an account that uses these
credentials."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"If the device is an HP StoreOnce D2D Backup system, upgrade to software
version 2.2.18 / 1.2.18 or later. 

Otherwise, set a strong password for this account or use ACLs to
restrict access to the host."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SSH User Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.lolware.net/hpstorage.html");
  # HP Bulletin ( HPSBST02890 )
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0eeaeffa");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

port = check_account(login:account, password:password, unix:FALSE);
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
