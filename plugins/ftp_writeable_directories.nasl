#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19782);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/12/23 19:06:02 $");

  script_osvdb_id(76);

  script_name(english:"FTP Writable Directories");
  script_summary(english:"Checks for FTP directories which are world-writable.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server contains world-writable directories.");
  script_set_attribute( attribute:"description", value:
"By crawling through the remote FTP server, Nessus discovered several
directories were marked as being world-writable.

This could have several negative impacts :

   * Temporary file uploads are sometimes immediately available to
     all anonymous users, allowing the FTP server to be used as
     a 'drop' point. This may facilitate trading copyrighted,
     pornographic, or questionable material.

   * A user may be able to upload large files that consume disk
     space, resulting in a denial of service condition.

   * A user can upload a malicious program. If an administrator
     routinely checks the 'incoming' directory, they may load a
     document or run a program that exploits a vulnerability
     in client software.");
  script_set_attribute(attribute:"solution",  value:
"Configure the remote FTP directories so that they are not world-
writable.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"1997/10/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("global_settings.inc");

global_var CheckedDir;
global_var WriteableDirs;
global_var Mode;
global_var Saved_in_KB;
global_var MODE_CHECK_PERM, MODE_WRITE, RMD_FAILED;

RMD_FAILED = FALSE;

function crawl_dir(socket, directory, level )
{
  local_var port, soc2, r, dirs,array, dir, sep, str, dirname;

  if ( level > 20 ) return 0;

  if ( directory[strlen(directory) - 1] == "/" )
    sep = "";
  else
    sep = "/";

  if ( CheckedDir[directory] ) return 0;
  port = ftp_pasv(socket:socket);
  if (! port ) return 0;
  soc2 = open_sock_tcp(port);
  if (! soc2 ) return 0;
  dirs = make_list();

  if ( Mode == MODE_WRITE )
  {
    str = "Nessus" + rand_str(length:8);
    send(socket:socket, data:'MKD ' + directory + sep + str  + '\r\n');
    r = ftp_recv_line(socket:socket);
    if ( r[0] == '2' )
    {
      WriteableDirs[directory] = 1;
      send(socket:socket, data:'RMD ' + directory + sep + str + '\r\n');
      r = ftp_recv_line(socket:socket);
      if ( r[0] != '2' ) Mode = MODE_CHECK_PERM;
      if ( ! Saved_in_KB )
      {
        if (! get_kb_item("ftp/writeable_dir"))
        replace_kb_item(name:"ftp/writeable_dir", value:directory);
        replace_kb_item(name:"ftp/"+port+"/writeable_dir", value:directory);
        replace_kb_item(name:"ftp/tested_writeable_dir", value:directory);
        replace_kb_item(name:"ftp/"+port+"/tested_writeable_dir", value:directory);
        Saved_in_KB ++;
      }
    }
  }

  send(socket:socket, data:'LIST ' + directory + '\r\n');
  CheckedDir[directory] = 1;

  r = ftp_recv_line(socket:socket);
  if ( r[0] != '1' ) {
    close(soc2);
    return 0;
  }

  while ( TRUE )
  {
    r = recv_line(socket:soc2, length:4096);
    if ( ! r ) break;
    if ( r[0] == 'd' )
    {
      array = eregmatch(pattern:"([drwxtSs-]*) *([0-9]*) ([0-9]*) *([^ ]*) *([0-9]*) ([^ ]*) *([^ ]*) *([^ ]*) (.*)", string:chomp(r));
      if ( max_index(array) >= 9 )
      {
        if ( Mode == MODE_CHECK_PERM )
        {
          if ( array[1] =~ "^d.......w." )
          {
            WriteableDirs[directory + sep + array[9]] = 1;
            if ( ! Saved_in_KB )
            {
              if (! get_kb_item("ftp/writeable_dir"))
              replace_kb_item(name:"ftp/writeable_dir", value:directory + sep + array[9]);
              replace_kb_item(name:"ftp/"+port+"/writeable_dir", value:directory + sep + array[9]);
              replace_kb_item(name:"ftp/"+port+"/tested_writable_dir", value:directory);
              replace_kb_item(name:"ftp/tested_writeable_dir", value:directory);
              Saved_in_KB ++;
            }
          }
        }
        if ( array[9] != "." && array[9] != ".." )
          dirs = make_list(dirs, directory + sep + array[9]);
      }
    }
    else if ( " <DIR> " >< r )
    {
      dirname = ereg_replace(pattern:".* <DIR> *(.*)$", replace:"\1", string:chomp(r));
      if( dirname != r ) dirs = make_list(dirs, directory + sep + dirname);
    }
  }
  close(soc2);
  r = recv_line(socket:socket, length:4096);
  foreach dir ( dirs )
  {
    crawl_dir(socket:socket, directory:dir, level:level + 1 );
  }
  return 0;
}

port = get_ftp_port(default: 21);
if ( ! get_kb_item("ftp/"+port+"/anonymous") )
  exit(0, "The FTP Server on port " + port + " does not allow anonymous logins.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

MODE_WRITE = 1;
MODE_CHECK_PERM = 2;

if ( safe_checks() )
  Mode = MODE_CHECK_PERM;
else
  Mode = MODE_WRITE;

login = "anonymous";
pwd   = "joe@";

soc = open_sock_tcp(port);
if ( ! soc ) audit(AUDIT_SOCK_FAIL, port);
if ( ! ftp_authenticate(socket:soc, user:login, pass:pwd) ) exit(0);

port2 = ftp_pasv(socket:soc);
if ( ! port2 ) exit(1, "PASV command failed on port "+port+".");

soc2 =  open_sock_tcp(port2);
if ( ! soc2 ) exit(1, "Failed to open a socket on PASV port "+port2+".");

send(socket:soc, data:'LIST .\r\n');
r = ftp_recv_line(socket:soc);
if ( r =~  "^1" )
{
  dir = ftp_recv_listing(socket:soc2);
  close(soc2);
  if ( " <DIR> " >< dir ) Mode = MODE_WRITE;
}
r = ftp_recv_line(socket:soc);

crawl_dir(socket:soc, directory:"/", level:0 );
ftp_close(socket:soc);

if ( isnull(WriteableDirs) || max_index(keys(WriteableDirs)) == 0 )
  audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);

if ( Mode == MODE_WRITE )
  report = 'By looking at the permissions, it was possible to gather the following list of writable directories :\n';
else
  report = 'By writing on the remote FTP server, it was possible to gather the following list of writable directories :\n';

foreach dir ( keys(WriteableDirs) )
{
  report += ' - ' + dir + '\n';
}

if ( report )
{
  security_warning(port:port, extra:'\n'+report);
}
