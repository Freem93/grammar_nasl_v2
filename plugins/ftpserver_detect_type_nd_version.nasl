#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10092);
 script_version("$Revision: 1.53 $");
 script_cvs_date("$Date: 2016/05/04 21:33:12 $");

 script_name(english:"FTP Server Detection");
 script_summary(english:"Checks for FTP services.");

 script_set_attribute(attribute:"synopsis", value:
"An FTP server is listening on a remote port.");
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the banner of the remote FTP server by
connecting to a remote port.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_require_ports("Services/ftp", 21);
 script_dependencies(
  "find_service_3digits.nasl",
  "doublecheck_std_services.nasl",
  "ftpd_no_cmd.nasl",
  "ftpd_any_cmd.nasl",
  "ftpd_bad_sequence.nasl",
  "fake_3digits.nasl",
  "ftp_kibuv_worm.nasl"
 );

 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

global_var  port;

function set_ftp_type()
{
  local_var type;
  type = _FCT_ANON_ARGS[0];
  set_kb_item(name: 'ftp/'+type, value:TRUE);
  set_kb_item(name: 'ftp/'+port+'/'+type, value:TRUE);
}

ports = get_ftp_ports(default:21);
if(isnull(ports))
  exit(0, "No FTP ports found.");

port = branch(ports);

banner = get_ftp_banner(port: port);
if (! banner) audit(AUDIT_NO_BANNER, port);

if(
    "421 Service not available" >!< banner &&
    "421 Too many connections" >!< banner &&
    "530 Connection refused" >!< banner
)
{
 if ("Core FTP Server" >< banner) set_ftp_type("coreftpserver");
 if ("NcFTPd" >< banner)
  set_ftp_type("ncftpd");
 if (" ProFTPD " >< banner || "-ProFTPD " >< banner || "(ProFTPD" >< banner)
  set_ftp_type("proftpd");
 if("icrosoft FTP" >< banner)
  set_ftp_type("msftpd");
 if("heck Point Firewall-1 Secure FTP" >< banner)
  set_ftp_type("fw1ftpd");
 if ( "Serv-U FTP Server" >< banner ||
  # nb: this seems to be for versions < 3.x.
  "Serv-U FTP-Server" >< banner )
  set_ftp_type("servu");
 if("Version wu-" >< banner || "Version wuftpd-" >< banner)
  set_ftp_type("wuftpd");
 if("xWorks" >< banner) set_ftp_type("vxftpd");
 if ("WS_FTP Server" >< banner) set_ftp_type("wsftp");
 if ("TurboFTP Server" >< banner) set_ftp_type("turboftp");
 if ("TYPSoft FTP" >< banner) set_ftp_type("typsoftftp");
 if ("Wing FTP Server" >< banner) set_ftp_type("wingftp");
 if ("FileZilla Server" >< banner) set_ftp_type("filezilla");
 if ("vsFTPd" >< banner) set_ftp_type("vsftpd");
 if ("ProRat" >< banner) set_ftp_type("prorat");
 if ("ProFTPD" >< banner && "500 GET not understood" >< banner)
  banner = banner - strstr(banner, "500 GET not understood");

 report = '\nThe remote FTP banner is :\n\n' + banner;
 security_note(port:port, extra:report);
}
