#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27041);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"K2 KeyServer Default Credentials");
  script_summary(english:"Tries to login to KeyServer with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote service is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote K2 KeyServer installation is configured to use default
credentials to control access.  Knowing these, an attacker can gain
control of the affected application.");
  script_set_attribute(attribute:"solution", value:
"Change the password for the 'Administrator' account using
KeyConfigure.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/k2-keyserver", 19283);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"k2-keyserver", default:19283, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = "Administrator";
pass = "Sassafras";


# Establish a connection and read the banner.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

banner = recv(socket:soc, length:1024, min:5);
if (strlen(banner) == 0 || stridx(banner, "/0 0 ") != 0) exit(0);


# Try to authenticate.
send(socket:soc, data:'USER ' + user + '\r\n');
res = recv(socket:soc, length:1024, min:5);
if (strlen(res) && stridx(res, "/0 0 OK") == 0)
{
  send(socket:soc, data:'PASS ' + pass + '\r\n');
  res = recv(socket:soc, length:1024, min:5);
  if (strlen(res) && stridx(res, "/0 0 OK") == 0)
  {
    report =
      'Nessus was able to gain access using the following credentials :\n' +
      '\n' +
      '  User Name : ' + user + '\n' +
      '  Password  : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
}
send(socket:soc, data:'QUIT\r\n');
close(soc);
