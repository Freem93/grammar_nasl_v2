#	
#	This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#

include("compat.inc");

if (description)
{
  # set script identifiers
  script_id(23642);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2006-5569");
  script_bugtraq_id(20721);
  script_osvdb_id(30010);

  script_name(english:"DataWizard FTPXQ Default Accounts");
  script_summary(english:"Tries to read a file via FTPXQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has one or more default test accounts.");
  script_set_attribute(attribute:"description", value:
"The version of DataWizard FTPXQ that is installed on the remote host
has one or more default accounts setup which can allow an attacker to
read and / or write arbitrary files on the system.");
  script_set_attribute(attribute:"see_also", value:
"http://attrition.org/pipermail/vim/2006-November/001107.html");
  script_set_attribute(attribute:"solution", value:
"Disable or change the password for any unnecessary user accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/14");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/25");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Justin Seitz");

  script_family(english:"FTP");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd", "global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  exit(0);

}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

#
# Verify we can talk to the FTP server, if not exit
#
port = get_ftp_port(default: 21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

banner = get_ftp_banner(port:port);
if (!banner || "FtpXQ FTP" >!< banner) audit(AUDIT_NOT_DETECT, 'FTPXQ', port);

#
#
# Now let's attempt to login with the default test account.
#
#

soc = open_sock_tcp(port);
if(!soc) exit(0);

n = 0;
acct[n] = "anonymous";
pass[n] = "";
n++;
acct[n] = "test";
pass[n] = "test";

file = '\\boot.ini';
contents = "";
info = "";
for (i=0; i<max_index(acct); i++) {
  login = acct[i];
  password = pass[i];

  if (ftp_authenticate(socket:soc, user:login, pass:password)) {
    info += "  " + login + "/" + password + '\n';

    if (strlen(contents) == 0) {
      #
      #
      # We have identified that we have logged in with the account, let's try to read boot.ini.
      #
      #
      port2 = ftp_pasv(socket:soc);
      if (!port2) exit(0);
      soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
      if (!soc2) exit(0);

      attackreq = string("RETR ", file);
      send(socket:soc, data:string(attackreq, "\r\n"));
      attackres = ftp_recv_line(socket:soc);
      if (egrep(string:attackres, pattern:"^(425|150) ")) {
        attackres2 = ftp_recv_data(socket:soc2);

        # There's a problem if it looks like a boot.ini.
        if ("[boot loader]" >< attackres2)
          contents = attackres2;
      }
    }
  }
}
ftp_close(socket:soc);

if (info) {
  info = string("The remote version of FTPXQ has the following\n",
    "default accounts enabled :\n\n",
    info);

  if ("test/test" >< info)
    info = string(info, "\n",
      "Note that the test account reportedly allows write access to the entire\n",
      "filesystem, although Nessus did not attempt to verify this.\n");

  if (contents)
    info = string(info, "\n",
      "In addition, Nessus was able to use one of the accounts to read ", file, " :\n",
      "\n",
      contents);

  security_warning(extra:"\n"+info, port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'FTPXQ', port);
