#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: 15 Apr 2003 00:34:13 -0000
#  From: denote <denote@freemail.com.au>
#  To: bugtraq@securityfocus.com
#  Subject: nb1300 router - default settings expose password
#

include("compat.inc");

if(description)
{
  script_id(11539);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_bugtraq_id(7359);
  script_osvdb_id(51636);

  script_name(english:"Default Password for FTP 'admin' Account");
  script_summary(english:"Checks for admin/password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router uses default credentials.");
  script_set_attribute(attribute:"description", value:
"The account 'admin' on the remote FTP server has the password 
'password'. An attacker may leverage this to gain access to the 
affected system and launch further attacks against it.

If the remote host is an NB1300 router, this would allow an attacker
to steal the WAN credentials of the user, or even to reconfigure the
router remotely.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/209");
  script_set_attribute(attribute:"solution", value:
"Change the admin password on this host.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:W/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
 
  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 
  script_dependencie(
    "ftpserver_detect_type_nd_version.nasl",
    "ftp_kibuv_worm.nasl",
    "DDI_FTP_Any_User_Login.nasl"
  );
  script_require_ports("Services/ftp", 21);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

#
# The script code starts here : 
#
include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item('ftp/'+port+'/AnyUser'))
  audit(AUDIT_FTP_RANDOM_USER, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if (ftp_authenticate(socket:soc, user:"admin", pass:"password"))
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to gain access using the following set of ' +
      'credentials :\n' +
      '\n' +
      '  Username : admin\n' +
      '  Password : password\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
