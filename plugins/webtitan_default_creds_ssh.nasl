#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76777);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_name(english:"WebTitan Default Credentials (ssh)");
  script_summary(english:"Attempts to login as admin.");

  script_set_attribute(attribute:"synopsis", value:"An account on the remote host uses a default password.");
  script_set_attribute(attribute:"description", value:
"The account 'admin' is using a default password. A remote,
unauthenticated attacker could exploit this to log in as a privileged
user and gain access to the WebTitan configuration menu.");
  script_set_attribute(attribute:"solution", value:"Log into the application and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webtitan:webtitan");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("default_account.inc");

login = "admin";
password = "hiadmin";

port = check_account(login:login, password:password, cmd:'', cmd_regex:'WebTitan :: Main Menu');
if (port) security_hole(port:port, extra:default_account_report());
else audit(AUDIT_HOST_NOT, "affected");
