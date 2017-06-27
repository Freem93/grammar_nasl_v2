#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29701);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"StarWind Control Port Default Credentials");
  script_summary(english:"Logs into the StarWind control port with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote service is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote StarWind control port is configured to use the default
credentials to control access.  Knowing these, an attacker can gain
administrative control of the affected application.");
  script_set_attribute(attribute:"solution", value:
"Edit the StarWind configuration file and change the login credentials
in the authentication section.  Then, restart the service to put the
changes into effect.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/starwind_ctl", 3261);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"starwind_ctl", default:3261, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


user = "test";
pass = "test";


# Establish a connection and read the banner.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

banner = recv(socket:soc, length:1024, min:24);
if (strlen(banner) == 0 || "StarWind iSCSI Target" >!< banner) exit(0);


# Try to authenticate.
send(socket:soc, data:"login " + user + " " + pass + '\r\n');
res = recv(socket:soc, length:1024, min:5);
if (strlen(res) && stridx(res, "200 Completed") == 0)
{
  report =
    '\n' +
    'Nessus was able to gain access using the following credentials :\n' +
    '\n' +
    '  User Name : ' + user + '\n' +
    '  Password  : ' + pass + '\n';

  # Collect some info about the remote devices.
  send(socket:soc, data:'list -what:"devices"\r\n');
  res = recv(socket:soc, length:1024, min:5);
  if (strlen(res) && stridx(res, "200 Completed.") == 0)
  {
    info = strstr(res, "200 Completed.") - "200 Completed.";
    info = str_replace(find:'\n', replace:'\n  ', string:info);

    report += '\n' +
      'In addition, it collected the following information about the\n' +
      'devices on the remote host.\n' +
      info;
  }
  if (report_verbosity > 0)  security_hole(port:port, extra:report);
  else security_hole(port);
}
send(socket:soc, data: 'quit\r\n');
close(soc);
