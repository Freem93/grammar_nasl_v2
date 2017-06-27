#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11779);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/05/05 17:46:22 $");

  script_name(english:"FTP Server Copyrighted Material Present");
  script_summary(english:"Checks if the remote ftp server hosts mp3/wav/asf/mpg files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is hosting potentially copyright infringing
files.");
  script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote FTP server is hosting mp3, wav,
avi, or asf files, which could be potentially copyright infringing.");
  script_set_attribute(attribute:"solution", value:
"Remove the files that are not in alignment with your organization's
security and acceptable use policies.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Copyright_infringement");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/26");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl", "smtp_settings.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

#
# The script code starts here :
#
include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default:21);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

function get_files(socket, basedir, level)
{
  local_var r,p,s,l,k,sl,m;

  send(socket:socket, data:'CWD ' + basedir + '\r\n');
  r = ftp_recv_line(socket:socket);
  if(!egrep(pattern:"^250 ", string:r))return NULL;

  if( level > 3 )
    return NULL;

  p = ftp_pasv(socket:socket);
  if(!p)return NULL;

  s = open_sock_tcp(p, transport:get_port_transport(port));
  if(!s)return NULL;
  send(socket:socket, data:'NLST .\r\n' );
  r = ftp_recv_line(socket:socket);
  if ( egrep(string:r, pattern:"^150 ") )
  {
    l = ftp_recv_listing(socket:s);
    r = ftp_recv_line(socket:socket);
  }
  close(s);
  l = split(l, keep:0);
  m = make_list();
  foreach k (l)
  {
    m = make_list(m, basedir + k);
  }

  foreach k (l)
  {
    sl = get_files(socket:socket, basedir:basedir + k + '/', level:level + 1);
    if( !isnull(sl) )
    m = make_list(m, sl);
  }
  return m;
}

if(!login)
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  login = "anonymous";
  domain = get_kb_item("Settings/third_party_domain");
  if(!domain) domain = "nessus.org";

  pass  = string("nessus@", domain);
}

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);
report = NULL;

r = ftp_authenticate(socket:soc, user:login, pass:pass);
if(r)
{
  files = get_files(socket:soc, basedir:"/", level:0);
  num_suspects = 0;
  foreach file (files)
  {
    if(ereg(pattern:".*\.(mp3|mpg|mpeg|ogg|avi|wav|asf|vob|wma|torrent)", string:file, icase:TRUE))
    {
      report += ' - ' + file + '\n';
      num_suspects ++;
      if( num_suspects > 40 )
      {
        report += ' - ... (more) ...\n';
        break;
      }
    }
  }
}
close(soc);

if( report != NULL )
{
  report = '
Here is a list of files which have been found on the remote FTP
server. Some of these files may contain copyrighted materials, such as
commercial movies or music files.

If any of these files contain copyrighted material, and if they are
freely swapped among users, your organization might be held liable
for copyright infringement by associations such as the RIAA or MPAA.
' + report;

  security_note(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
