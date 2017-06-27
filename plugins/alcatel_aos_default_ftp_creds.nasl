#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70210);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/07 17:25:13 $");

  script_name(english:"Alcatel OmniSwitch Default Credentials (ftp)");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device can be accessed with default credentials via FTP.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Alcatel OmniSwitch by providing
the default credentials via FTP. A remote attacker could exploit this
to gain administrative control of the remote device.");
  script_set_attribute(attribute:"solution", value:
"Change the default password or block access to the port.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:alcatel-lucent:omniswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alcatel:aos");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user   = "admin";
passwd = "switch";

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (ftp_authenticate(socket:soc, user:user, pass:passwd))
{
  # nb: Alcatel switches have a non RFC-compliant FTP server which does not start its lines with a 230 code
  r = recv_line(socket:soc, length:1024);
  ftp_close(socket:soc);
  if ( "Software Version "  >!< r ) exit(0, "The FTP server listening on port "+port+" is not an Alcatel OmniSwitch.");

  if (report_verbosity > 0)
  {
    report = strcat( "
Nessus was able to log into the remote FTP server using the following
default credentials :

  User      : ", user, "
  Password  : ", passwd,"

  Remote OS : ", r);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}

ftp_close(socket:soc);
audit(AUDIT_LISTEN_NOT_VULN, "", port);
