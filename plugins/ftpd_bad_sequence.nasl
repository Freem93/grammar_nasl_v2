#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32375);
 script_version ("$Revision: 1.11 $");
 script_name(english:"FTP Server Bad Command Sequence Accepted (possible backdoor/proxy)");
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP service accepts commands in any order." );
 script_set_attribute(attribute:"description", value:
"The remote server advertises itself as being an FTP server, but it
accepts commands sent out of order, which indicates that it may be a
backdoor or a proxy. 

Further FTP tests on this port will be disabled to avoid false alerts." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/19");
 script_cvs_date("$Date: 2015/12/23 21:38:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks that the FTP server rejects commands in wrong order");
 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");
 script_copyright(english: "This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl", "logins.nasl", "ftpd_no_cmd.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_keys("Settings/ExperimentalScripts");
 exit(0);
}

#
include("audit.inc");
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

global_var port;

function test(soc)
{
 local_var r, r2, score;
 score = 0;
 r = ftp_recv_line(socket: soc, retry: 2);
 if (! r)
 {
  debug_print('No FTP welcome banner on port ', port, '\n');
## set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
  set_kb_item(name: 'ftp/'+port+'/no_banner', value: TRUE);
  return NULL;
 }
 debug_print(level: 2, 'Banner = ', r);

 if (r =~ '^[45][0-9][0-9] ' || 
     match(string: r, pattern: 'Access denied*', icase: 1))
 {
   debug_print('FTP server on port ', port, ' is closed\n');
   set_kb_item(name: 'ftp/'+port+'/denied', value: TRUE);
   return NULL;
  }

 send(socket: soc, data: 'PASS '+rand_str()+'\r\n');
 r = ftp_recv_line(socket: soc, retry: 2);
 if (r =~ '^230[ -]') # USER logged in
 {
  debug_print('PASS accepted without USER\n');
  set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
  score ++;
 }

 send(socket: soc, data: 'USER '+rand_str()+'\r\n');
 r = ftp_recv_line(socket: soc, retry: 2);
 if (r !~ '^331[ -]') return score;

 send(socket: soc, data: 'QUIT\r\n');
 r = ftp_recv_line(socket: soc, retry: 2);
 if (! r) return score;
 send(socket: soc, data: 'QUIT\r\n');
 r2 = ftp_recv_line(socket: soc, retry: 2);
 if (r =~ '^221[ -]' && r2 =~ '^221[ -]')
 {
  debug_print('QUIT accepted twice\n');
  score ++;
 }
 return score;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! experimental_scripts)
 exit(0, 'This script only runs in experimental mode\n');

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, 'TCP connection failed to port '+port+'.');

score = test(soc: soc);

if (report_paranoia >= 2 && score >= 1 || score >= 2)
{
 security_note(port);
 set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
}

ftp_close(socket: soc);
