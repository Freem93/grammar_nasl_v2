#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73189);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_name(english:"3Com Switch Default Admin Credentials");
  script_summary(english:"Tries to log into the remote host");

  script_set_attribute(attribute:"synopsis", value:
"The remote system can be accessed with a default set of credentials.");
  script_set_attribute(attribute:"description", value:
"The remote device is a 3Com Switch that uses a set of known, default
credentials. Knowing these, an attacker able to connect to the service
can gain control of the device.");
  script_set_attribute(attribute:"solution", value:"Log into the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:3com_switch");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include("audit.inc");
include("default_account.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

logins = make_array();
passes = make_array();
i = 0;

logins[i] = "Admin";
passes[i] = "3Com";
i++;

logins[i] = "admin";
passes[i] = "";
i++;

logins[i] = "admin";
passes[i] = "admin";
i++;

logins[i] = "manager";
passes[i] = "manager";
i++;

logins[i] = "security";
passes[i] = "security";
i++;


n = i;
report = '';
for (i=0; i<n; i++)
{
  res = _check_telnet(
    port            : port,
    login           : logins[i],
    password        : passes[i],
    cmd             : '',
    cmd_regex       : "(Administer system-level functions|Logout of the Command Line Interface)"
  );
  if (res)
  {
    report += '\n  Login : ' + logins[i] +
              '\n  Pass  : ' + passes[i] +
              '\n';
    if (!thorough_tests) break;
  }
}

if (report)
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to gain access using the following credentials :' +
             '\n' +
             report;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
