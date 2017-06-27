#
# This script is copyright  2001 by EMAZE Networks S.p.A.
# under the General Public License (GPL). All Rights Reserved.
#
# changes by rd: added risk factor & fix

# Changes by Tenable:
# - Revised plugin title (1/28/2009)
# - Fixed typos in the description (11/30/2012)

bracket = raw_string(0x7B);

include("compat.inc");

if (description)
{
  script_id(10821);
  script_version("$Revision: 1.49 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2001-0249", "CVE-2001-0550");
  script_bugtraq_id(2550, 3581);
  script_osvdb_id(686, 8681);

  script_name(english:"Multiple FTPD glob Command Arbitrary Command Execution");
  script_summary(english:"Check if the remote FTPD is affected by a glob heap corruption vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The FTPD glob vulnerability manifests itself in handling the glob
command. The problem is not a typical buffer overflow or format string
vulnerability, but a combination of two bugs - an implementation of
the glob command that does not properly return an error condition when
interpreting the string 'bracket', and then frees memory which may
contain user-supplied data.

An attacker who is able to log in to a vulnerable server, including
users with anonymous access, can exploit this to execute arbitrary
code with the privileges of the FTP service.");
  # https://web.archive.org/web/20040820110551/http://archives.neohapsis.com/archives/vulnwatch/2001-q3/0003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0332633c");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Nov/237");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Nov/258");
  script_set_attribute(attribute:"solution", value:"Contact your vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"Copyright (C) 2001-2016 E*Maze");

  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "os_fingerprint.nasl", "solaris251_103603.nasl", "solaris251_x86_103604.nasl", "solaris26_106301.nasl", "solaris26_x86_106302.nasl", "solaris7_110646.nasl", "solaris7_x86_110647.nasl", "solaris8_111606.nasl", "solaris8_x86_111607.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

if ( get_kb_item("BID-2550") ) exit(0);

port = get_ftp_port(default: 21);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(safe_checks())login = 0;


if (login)
{
	soc = open_sock_tcp(port);
	if (!soc)
		exit(0);

	if (ftp_authenticate(socket:soc, user:login, pass:password))
	{
 		c = string("CWD ~", bracket, "\r\n");
     		d = string("CWD ~*", bracket, "\r\n");

		send(socket:soc, data:c);
     		b = ftp_recv_line(socket:soc);

 		send(socket:soc, data:d);
		e = ftp_recv_line(socket:soc);

		#
		# Buggy version. no known exploits
		#

		buggy =
"You seem to be running an FTP server which is vulnerable to the 'glob
heap corruption' flaw, but which can not be exploited on this server.";



		#
		# Vulnerable version. Working exploit has been written
		#
		vuln =
"You seem to be running an FTP server which is vulnerable to the 'glob
heap corruption' flaw, which is known to be exploitable remotely against
this server. An attacker may use this flaw to execute arbitrary commands
on this host.";


		#
		# Check if the connection is lost
		# if it is, the daemon is vulnerable
		# linux/bsd: wuftpd, beroftpd
		# solaris ftpd
		#

		if ((!b) || (!e))
		{
			security_hole(port:port, extra:vuln);
			exit(0);
		}

		#
		# Freebsd / Openbsd command successful.
		# buggy version
		#
		if ((b >< "250 CWD command successful") ||
		    (e >< "250 CWD command successful"))
		{
		   	security_hole(port:port, extra:buggy);
			exit(0);
		}

		#
		# Netbsd vulnerable
		#
		if((b >< ":") || (e >< ":"))
		{
			security_hole(port:port, extra:vuln);
			exit(0);
		}

		#
		# Aix buggy
		#
		if ((b >< "550 Unknown user name after ~") ||
		    (e >< "550 Unknown user name after ~"))
		{
			security_hole(port:port, extra:buggy);
			exit(0);
		}

		#
		# MacOS X Darwin buggy
		#
		if ((b >< "550 ~: No such file or directory") ||
		    (e >< "550 ~: No such file or directory"))
		{
		   	security_hole(port:port, extra:buggy);
			exit(0);
		}

		#
		# The non vulnerable version
		#
     		ftp_close(socket:soc);

		exit(0);
	}

	ftp_close(socket: soc);
}




os = get_kb_item("Host/OS");
if(os)
{
 if(egrep(pattern:".*FreeBSD (4\.[5-9]|5\..*).*", string:os))exit(0);
}




#
# We weren't able to login into the ftp server.
# check the banner instead
#
banner = get_ftp_banner(port: port);

if (!banner)
	exit(0);

#
# FTP server 4.1 (aix/ultrix), 1.1. (hp-ux), 6.00 (darwin), 6.00LS (freebsd)
#

# wu-ftpd 2.6.1-20 is not vulnerable
if(egrep(pattern:"(wu|wuftpd)-2\.6\.1-[2-9][0-9].*", string:banner))exit(0);


if ( "PHNE_27765" >< banner ||
     "PHNE_29461" >< banner ||
     "PHNE_30432" >< banner ||
     "PHNE_31931" >< banner ||
     "PHNE_34544" >< banner ||
     "PHNE_30990" >< banner ) exit(0);

if (
	egrep(pattern:
		"(wu|wuftpd)-([0-1]|(2\.([0-5][^0-9]|6\.[0-1]))).*",
	string:banner) ||
	egrep(pattern:
		"BeroFTPD.*",
	string:banner) ||
	egrep(pattern:
		"NetBSD-ftpd (199[0-9]|200[0-1]).*",
	string:banner) ||
	egrep(pattern:
		"Digital UNIX Version [0-5]\..*",
	string:banner) ||
	egrep(pattern:
		"SunOS [0-5]\.[0-8].*",
	string:banner) ||
	egrep(pattern:
		"FTP server.*Version (1\.[0-1]\.|4\.1|6\.00|6\.00LS).*",
	string:banner)	||
	egrep(pattern:
		"FTP server .SRPftp 1\.[0-3].*",
	      string:banner))
	{
	banvuln =
"Nessus relied solely on the banner of the server to issue this warning,
so this alert might be a false positive.
A valid username/password is needed to fully check this vulnerability";
	security_hole(port:port, extra:banvuln);
	exit(0);
}

