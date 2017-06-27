#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25040);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/05/17 17:13:09 $");

 script_cve_id("CVE-2007-2165");
 script_bugtraq_id(23546);
 script_osvdb_id(34602);
 
 script_name(english:"ProFTPD Auth API Multiple Auth Module Authentication Bypass");
 script_summary(english:"Attempts to bypass FTP authentication");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass the authentication scheme of the remote FTP
server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running ProFTPd.  Due to a bug in the way the
remote server is configured and the way it processes the USER and PASS
commands, it is possible to log into the remote system by supplying
invalid credentials.");
 script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=2922");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest (CVS) version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/19");
 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencie("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/proftpd");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);
if ( get_kb_item("ftp/" + port + "/AnyUser") ) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner || "ProFTPD" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if( ! soc ) exit(1);
#
# Debian ships with proxy,www-data,irc,list,backup. Try 'bin' for good measure as well
#
foreach user (make_list("proxy", "clamav", "bin"))
{
  pass = "*";
  if (ftp_authenticate(socket:soc, user:user, pass:pass))
  {
    listing = NULL;

    port2 = ftp_pasv(socket:soc);
    if (! port2) exit(1);

      soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
      if (soc2)
      {
        send(socket:soc, data:'LIST\r\n');
        listing = ftp_recv_listing(socket:soc2);
        close(soc2);
      }

    info = 'Nessus was able to log in using the credentials "' + user + '/' + pass + '"';
    if (listing)
      info = info + ' and obtain\nthe following listing of the FTP root :\n' + listing;
    else
      info = info + '.\n';

    report = '\n' + info;
    security_warning(port:port, extra:report);

    break;
  }
}
close(soc);
