#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55900);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 20:59:26 $");

  script_cve_id("CVE-1999-0502");

  script_name(english:"Remote Authentication Message Check");
  script_summary(english:"Attempts to log into the remote host with random credentials");

  script_set_attribute(attribute:"synopsis", value:
"Check whether it is possible to determine if remote accounts are
valid.");
  script_set_attribute(attribute:"description", value:
"In order to avoid false positives, this plugin determines if the remote
system accepts any kind of login.  Some SSH implementations claim that a
login has been accepted when it has not.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl");
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
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if ( report_paranoia == 0 )
{
 port = check_account(login:rand_str(length:8), password:rand_str(length:8), unix:TRUE, check_mocana:TRUE);
 if(port)
  set_kb_item(name:"login/unix/auth/broken", value:TRUE);
 else
 {
  port = check_account(login:rand_str(length:8), unix:TRUE, check_mocana:TRUE);
  if(port) set_kb_item(name:"login/unix/auth/broken", value:TRUE);
 }
}

port = check_account(login:rand_str(length:8), password:rand_str(length:8), unix:FALSE, check_mocana:TRUE);
if ( port )
  set_kb_item(name:"login/auth/broken", value:TRUE);
else
{
 port = check_account(login:rand_str(length:8), unix:FALSE, check_mocana:TRUE);
 if(port) set_kb_item(name:"login/auth/broken", value:TRUE);
}
