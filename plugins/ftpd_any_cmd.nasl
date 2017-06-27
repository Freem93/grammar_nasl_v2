#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32373);
 script_version ("$Revision: 1.10 $");
 script_name(english:"FTP Server Any Command Accepted (possible backdoor/proxy)");
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is not working properly." );
 script_set_attribute(attribute:"description", value:
"The remote server advertises itself as being a FTP server, but it
accepts any command, which indicates that it may be a backdoor or a
proxy. 

Further FTP tests on this port will be disabled to avoid false alerts." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/19");
 script_cvs_date("$Date: 2015/12/23 21:38:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks that the FTP server rejects invalid commands");
 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");
 script_copyright(english: "This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl", "logins.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("Settings/ExperimentalScripts");
 exit(0);
}

include("audit.inc");
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

if (! experimental_scripts) exit(0);

login = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if (supplied_logins_only && (isnull(login) || isnull(pass)))
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! login) login = "anonymous";
if (! pass) pass = "bounce@nessus.org";

port = get_ftp_port(default: 21);

ftpcmd["CWD"]=1;  ftpcmd["XCWD"]=1; ftpcmd["CDUP"]=1; ftpcmd["XCUP"]=1;
ftpcmd["SMNT"]=1; ftpcmd["QUIT"]=1; ftpcmd["PORT"]=1; ftpcmd["PASV"]=1; 
ftpcmd["EPRT"]=1; ftpcmd["EPSV"]=1; ftpcmd["ALLO"]=1; ftpcmd["RNFR"]=1; 
ftpcmd["RNTO"]=1; ftpcmd["DELE"]=1; ftpcmd["MDTM"]=1; ftpcmd["RMD"]=1; 
ftpcmd["XRMD"]=1; ftpcmd["MKD"]=1;  ftpcmd["XMKD"]=1; ftpcmd["PWD"]=1; 
ftpcmd["XPWD"]=1; ftpcmd["SIZE"]=1; ftpcmd["SYST"]=1; ftpcmd["HELP"]=1;  
ftpcmd["NOOP"]=1; ftpcmd["FEAT"]=1; ftpcmd["OPTS"]=1; ftpcmd["AUTH"]=1; 
ftpcmd["CCC"]=1;  ftpcmd["CONF"]=1; ftpcmd["ENC"]=1;  ftpcmd["MIC"]=1; 
ftpcmd["PBSZ"]=1; ftpcmd["PROT"]=1; ftpcmd["TYPE"]=1; ftpcmd["STRU"]=1; 
ftpcmd["MODE"]=1; ftpcmd["RETR"]=1; ftpcmd["STOR"]=1; ftpcmd["STOU"]=1; 
ftpcmd["APPE"]=1; ftpcmd["REST"]=1; ftpcmd["ABOR"]=1; ftpcmd["USER"]=1; 
ftpcmd["PASS"]=1; ftpcmd["ACCT"]=1; ftpcmd["REIN"]=1; ftpcmd["LIST"]=1;  

function test(port, login, pass)
{
 local_var cmd, r, soc;
 soc = open_sock_tcp(port);
 if (! soc) return NULL;

 r = ftp_recv_line(socket: soc, retry: 2);
 if (! r)
 {
  debug_print('No FTP welcome banner on port ', port, '\n');
## set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
  set_kb_item(name: 'ftp/'+port+'/no_banner', value: TRUE);
  ftp_close(socket: soc);
  return NULL;
 }
 debug_print(level: 2, 'Banner = ', r);

 if (r =~ '^[45][0-9][0-9] ' || 
     match(string: r, pattern: 'Access denied*', icase: 1))
 {
  debug_print('FTP server on port ', port, ' is closed\n');
  set_kb_item(name: 'ftp/'+port+'/denied', value: TRUE);
  ftp_close(socket: soc);
  return NULL;
 }

 send(socket: soc, data: 'USER '+login+'\r\n');
 r = ftp_recv_line(socket: soc, retry: 2);
 if (r !~ '230') # USER logged in
 {
  send(socket: soc, data: 'PASS '+pass+'\r\n');
  r = ftp_recv_line(socket: soc, retry: 2);
  if (r !~ '2[0-9][0-9] ')
  {
   debug_print('Cannot login to FTP server on port ', port, '. Provide a valid account!\n');
   set_kb_item(name: 'ftp/'+port+'/denied', value: TRUE);
   ftp_close(socket: soc);
   return NULL;
  }
 }
 repeat
  cmd = rand_str(length: 4, charset: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
 until (! ftpcmd[cmd]);
 send(socket: soc, data: cmd +  '\r\n');
 r = ftp_recv_line(socket: soc, retry: 2);
 ftp_close(socket: soc);
 if (strlen(r) == 0 || r =~ '^5[0-9][0-9]')
  return 0;
 debug_print('FTP server on port ', port, ' accepts command ', cmd, '\n');
 return 1;
}

ok = 0;
miserable_failure = 0;
for (i = 0; i < 5; i ++)
{
 z = test(port: port, login: login, pass: pass);
 if (isnull(z))
  if (miserable_failure ++ > 1)
  {
   debug_print(miserable_failure, ' miserables failures! Exiting\n');
   exit(0);
  }
 if (z) 
  if (++ ok > 2)
  {
   security_note(port);
   set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
   exit(0);
  }
}
