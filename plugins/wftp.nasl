#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(10305);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2017/03/03 22:36:31 $");

  script_cve_id("CVE-1999-0200");
  script_bugtraq_id(80910);
  script_osvdb_id(241);

  script_name(english:"WFTP Unpassworded Guest Account");
  script_summary(english:"Checks if any account can access the FTP server.");

  script_set_attribute(attribute:'synopsis', value:
"The remote FTP service allows access without authentication through a
guest account.");
  script_set_attribute(attribute:'description', value:
"The remote FTP server accepts any user/password combination. This can
allow remote attackers to access the FTP account, which can lead to
information disclosure and uploads of arbitrary files on the remote
host.");
  script_set_attribute(attribute:'solution', value:
"Upgrade to a supported version of Windows or disable the FTP server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

  script_dependencie("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include('ftp_func.inc');
include('misc_func.inc');

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item('ftp/'+port+'/AnyUser'))
  audit(AUDIT_FTP_RANDOM_USER, port);

soc = open_sock_tcp(port);
if (!soc)  audit(AUDIT_SOCK_FAIL, port);

user = rand_str(length:8);
pass = rand_str(length:8);

if (ftp_authenticate(socket:soc, user:user, pass:pass))
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  User     : ' + user + '\n' +
      '  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
