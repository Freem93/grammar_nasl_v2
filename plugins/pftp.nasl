#
# (C) Tenable Network Security, Inc.
#

# Thanks to Overlord <mail_collect@gmx.net> for supplying me
# with the information for this problem as well as a copy of a
# vulnerable version of PFTP

include("compat.inc");

if(description)
{
  script_id(10508);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/03/03 22:22:42 $");

  script_osvdb_id(407);

  script_name(english: "PFTP Default Unpassworded Account");
  script_summary(english:"Checks for a blank account.");
 
  script_set_attribute(attribute:"synopsis", value:
"It was possible to login to the remote system with an unpassworded
account.");
  script_set_attribute(attribute:"description", value:
"It was possible to log into the remote FTP server as ' ' / ' '. If the
remote server is PFTP, then anyone can use this account to read
arbitrary files on the remote host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade PFTP to version 2.9g or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/09/10");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english: "FTP");
 
  script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");

  script_dependencie(
    "ftpserver_detect_type_nd_version.nasl",
    "ftp_kibuv_worm.nasl",
    "DDI_FTP_Any_User_Login.nasl"
  );
  script_require_ports("Services/ftp", 419);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');

port = get_ftp_port(default:419);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (!ftp_authenticate(socket:soc, user:" ", pass:" "))
  audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);

set_kb_item(name:"ftp/pftp_login_problem", value:TRUE);
close(soc);

if (report_verbosity > 0)
{
  report = '\nNessus was able to gain access with a blank username and password.';
  security_hole(port:port, extra:report);
}
else security_hole(port);
exit(0);
