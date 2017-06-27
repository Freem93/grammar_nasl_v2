#
# (C) Tenable Network Security, Inc.
#

# References:
#
# From: matrix@infowarfare.dk
# Subject: Directory traversal vulnerabilities found in NITE ftp-server version 1.83
# Date: Wed, 15 Jan 2003 13:10:46 +0100
#
# From: "Peter Winter-Smith" <peter4020@hotmail.com>
# To: vulnwatch@vulnwatch.org, vuln@secunia.com, bugs@securitytracker.com
# Date: Wed, 06 Aug 2003 19:41:13 +0000
# Subject: Directory Traversal Vulnerability in 121 WAM! Server 1.0.4.0
#
# Vulnerable:
# NITE ftp-server version 1.83
# 121 WAM! Server 1.0.4.0

include("compat.inc");

if (description)
{
  script_id(11466);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2003-1349");
  script_bugtraq_id(6648);
  script_osvdb_id(2126, 51637);

  script_name(english:"Multiple FTP Server Traversal Arbitrary File/Directory Access");
  script_summary(english:"Attempts to set the current directory to the root of the disk");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server allows arbitrary file access");
  script_set_attribute(attribute:"description", value:
"The remote FTP server allows anybody to switch to the root directory
and read potentialy sensitive files.");
  script_set_attribute(attribute:"solution", value:
"If this is Thomas Krebs Nite Server, upgrade to version 1.85 or later.
Otherwise contact your vendor for the appropriate patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q1/23");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"FTP");

  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_keys("ftp/login", "Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1);

if (! ftp_authenticate(socket:soc, user: "anonymous", pass: "nessus@example.com"))
{
  ftp_close(socket:soc);
  exit(0, "The FTP server on port "+port+" rejects anonymous connections.");
}
send(socket: soc, data: 'CWD\r\n');
r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      cur1 = v[1];
      break;
    }
  }
}

# Loop on vulnerable patterns
dirs = make_list("\..\..\..\..\..", "/../");
foreach d (dirs)
{
send(socket: soc, data: 'CWD ' + d + '\r\n');

r = ftp_recv_line(socket: soc);
send(socket: soc, data: 'PWD\r\n');
r = ftp_recv_line(socket: soc);
matches = egrep(string:r, pattern:'^[0-9]+ *"([^"]+)"');
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    v = eregmatch(string:match, pattern:'^[0-9]+ *"([^"]+)"');
    if (! isnull(v)) {
      cur2 = v[1];
      break;
    }
  }
}

if (cur1 && cur2)
{
  if (cur1 != cur2)
    security_warning(port);
  ftp_close(socket: soc);
  exit(0);
}

p = ftp_pasv(socket:soc);
if(p)
{
  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if(soc2)
  {
     send(socket:soc, data: 'LIST\r\n');
     r = ftp_recv_listing(socket:soc2);
     r = tolower(r);
     r2 = ftp_recv_line(socket: soc);
     close(soc2);
     if ("autoexec.bat" >< r || "boot.ini" >< r || "config.sys" >< r)
     {
       security_warning(port);
       break;
     }
   }
}
}
ftp_close(socket: soc);
