#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40332);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2017/03/03 22:36:31 $");
 
 script_name(english:"Wyse Device Manager Default FTP Account");
 script_summary(english:"Attempts to log in via FTP using credentials associated with Wyse Device Manager.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an account that is protected with default
credentials." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server has an account with a known username / password
combination, possibly created as part of an installation of Wyse
Device Manager. An attacker may be able to use this to gain
authenticated access to the system, which could allow for other
attacks against the affected application and host.");
 script_set_attribute(attribute:"solution", value:
"Change the password associated with the reported username.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:dell:wyse_device_manager");
 script_set_attribute(attribute:"default_account", value:"true");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

 script_dependencie("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');

port = get_ftp_port(default: 419);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

user   = "rapport";
passwd = "r@p8p0r+";

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);

if (ftp_authenticate(socket:soc, user:user, pass:passwd))
{
  ftp_close(socket:soc);

  if (report_verbosity > 0)
  {
    report =
     '\n' +
     'Nessus was able to log into the remote FTP server using the\n' +
     'following default credentials :\n' +
     'User     : ' + user + '\n' +
     'Password : ' + passwd + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

ftp_close(socket:soc);
audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
