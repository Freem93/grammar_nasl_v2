#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10080);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/03/03 22:16:03 $");

  script_cve_id("CVE-1999-0452");
  script_bugtraq_id(82858);
  script_osvdb_id(70);

  script_name(english:"Linux FTP Server Backdoor Detection");
  script_summary(english:"Checks for the NULL ftpd backdoor.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has a backdoor.");
  script_set_attribute(attribute:"description", value:
"There is a backdoor in the old FTP daemons of Linux that allows remote
users to log in as 'NULL' with password 'NULL'. These credentials
provide root access.");
  script_set_attribute(attribute:"solution", value:
"Upgrade your FTP server to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"1990/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");
 
  script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");
 
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "DDI_FTP_Any_User_Login.nasl");
  script_require_ports("Services/ftp", 21);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#
# The script code starts here : 
#

include("audit.inc");
include("global_settings.inc");
include('ftp_func.inc');

port = get_ftp_port(default: 21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item("ftp/" + port + "/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (ftp_authenticate(socket:soc, user:"NULL", pass:"NULL"))
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  User     : NULL\n' +
      '  Password : NULL\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
