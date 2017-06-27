#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76073);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_name(english:"Brocade Fabric OS Default Credentials");
  script_summary(english:"Tries to log into the remote host");

  script_set_attribute(attribute:"synopsis", value:"The remote system can be accessed with a default set of credentials.");
  script_set_attribute(attribute:"description", value:
"The remote device is a Brocade Fabric OS device that uses a set of
known, default credentials. Knowing these, an attacker able to connect
to the service can gain control of the device.");
  # http://community.brocade.com/t5/User-Contributed/How-To-Find-Default-Username-and-Password/ta-p/36420
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5433090");
  script_set_attribute(attribute:"solution", value:"Log into the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:brocade:fabric_os");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");


  script_dependencies("account_check.nasl", "ssh_detect.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}


include("audit.inc");
include("default_account.inc");
include("global_settings.inc");
include("misc_func.inc");


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


cmd = "version";
cmd_pat = "Fabric OS:[ \t]+v[0-9]+(\.[0-9]+)+";

logins = make_array();
passes = make_array();
i = 0;

logins[i] = "admin";
passes[i] = "password";
i++;

logins[i] = "root";
passes[i] = "fibranne";
i++;


n = i;
report = '';
for (i=0; i<n; i++)
{
  port = check_account(
    login           : logins[i],
    password        : passes[i],
    noexec          : TRUE,
    cmd             : cmd,
    cmd_regex       : cmd_pat
  );
  if (port)
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
             report +
             default_account_report(cmd:cmd);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
audit(AUDIT_HOST_NOT, "affected");
