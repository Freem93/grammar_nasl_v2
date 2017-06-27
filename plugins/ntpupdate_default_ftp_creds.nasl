#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73188);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_osvdb_id(100729);

  script_name(english:"Default FTP Credentials (ntpupdate / ntpupdate)");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote FTP server by providing default
credentials. A remote attacker could exploit this to gain access to
the remote server.

These credentials are known to apply to Schneider Electric Modicon
M340 for Ethernet devices; however, they may apply to other FTP
services as well.");
  # http://dariusfreamon.wordpress.com/2013/12/08/schneider-modicon-m340-for-ethernet-multiple-default-credentials/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d597c448");
  script_set_attribute(attribute:"solution", value:
"Change the default password or block access to the port.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:schneider-electric:modicon:m340");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"FTP");

  script_dependencies("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default:21);

if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user   = "ntpupdate";
passwd = "ntpupdate";

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (ftp_authenticate(socket:soc, user:user, pass:passwd))
{
  ftp_close(socket:soc);

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to log into the remote FTP server using the following' +
      '\n' + 'default credentials :\n' +
      '\n  User     : ' + user +
      '\n  Password : ' + passwd +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  ftp_close(socket:soc);
  exit(0, "The FTP server on port " + port + " is not affected.");
}
