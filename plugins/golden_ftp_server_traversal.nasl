#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18194);
  script_version("$Revision: 1.24 $");

  script_cve_id("CVE-2005-1484");
  script_bugtraq_id(13479);
  script_osvdb_id(16260);

  script_name(english:"Golden FTP Server Pro GET Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Golden FTP Server installed on the remote host is prone
to a directory traversal attack.  Specifically, an attacker can read
files located outside a share with '\\..' sequences subject to the
privileges of the FTP server process." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/32" );
 script_set_attribute(attribute:"solution", value:
"Use an FTP proxy to filter malicious character sequences, place the
FTP root on a separate drive, or restrict access using NTFS." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/03");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:kmint21_software:golden_ftp_server");
 script_end_attributes();

 
  script_summary(english:"Checks for directory traversal vulnerability in Golden FTP Server");
  script_category(ACT_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include('global_settings.inc');


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
if (!user || !pass) {
  exit(0, "ftp/login and/or ftp/password are empty");
}


port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port);
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
  close(soc);
  exit(1, "Cannot login on port "+port+" with supplied FTP credentials");
}


# Make sure it's Golden FTP Server.
send(socket:soc, data:'SYST\r\n');
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s)
{
 close(soc); exit(0, "Golden FTP Server is not running on port "+port);
}


port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, "Cannot establish FTP passive connection.");
soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);
if (!soc2) exit(1, "Cannot connect on port "+port2+" (passive connection)");

# Identify some directories on the remote.

send(socket:soc, data: 'LIST /\r\n');
s = recv_line(socket:soc, length:4096);
if (s =~ "^1[0-9][0-9] ") {
  listing = ftp_recv_listing(socket:soc2);
  s = recv_line(socket:soc, length:4096);
}
ndirs = 0;
foreach line (split(listing, keep:FALSE)) {
  if (line =~ "^d") {
    # nb: dirs may have spaces so we can't just use a simple regex.
    dirs[++ndirs] = substr(line, 55);
  }
  # 10 directories should be enough for testing.
  if (ndirs > 10) break;
}


# Try to exploit the vulnerability.
foreach dir (dirs) {
  # Iterate several times while trying to get the file's size.
  #
  # nb: this is a handy way to see if the file can be 
  #     retrieved without going through the hassle of 
  #     actually retrieving it.
  i = 0;
  file = "msdos.sys";
  while (++i < 5) {
    c = strcat('SIZE /', dir, '/\\..\\', file, '\r\n');
    send(socket:soc, data: c);
    s = ftp_recv_line(socket:soc);

    # If we get a 213 followed by a size, there's a problem.
    if (egrep(string:s, pattern:"^213 [0-9]+")) {
      security_warning(port);
      exit(0);
    }
  }
}


# Close the connections.
close(soc2);
ftp_close(socket:soc);
exit(0, "The FTP server on port "+port+" is unaffected");
