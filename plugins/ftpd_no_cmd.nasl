#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(32374);
 script_version ("$Revision: 1.11 $");
 script_name(english:"FTP Server No Command Accepted (possible backdoor/proxy)");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is not working properly.");
 script_set_attribute(attribute:"description", value:
"The remote server advertises itself as an FTP server, but it does not
accept valid commands, which indicates that it may be a backdoor or a
proxy. 

Further FTP tests on this port will be disabled to avoid false alerts." );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/19");
 script_cvs_date("$Date: 2017/02/03 16:29:56 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Checks that the FTP server accepts common commands");
 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");
 script_copyright(english: "This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl", "logins.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("Settings/ExperimentalScripts");
 exit(0);
}

#
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

if (! experimental_scripts)
 exit(0);

login = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");
# if (! login) login = "anonymous";
# if (! pass) pass = "bounce@nessus.org";

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) audit(AUDIT_SOCK_FAIL, port);

r = ftp_recv_line(socket: soc, retry: 3);
if (! r)
{
  debug_print('No FTP welcome banner on port ', port, '\n');
## set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
  set_kb_item(name: 'ftp/'+port+'/no_banner', value: TRUE);
  ftp_close(socket: soc);
  audit(AUDIT_NO_BANNER, port);
}
debug_print(level: 2, 'Banner = ', r);

if (r =~ '^[45][0-9][0-9] ' ||
     match(string: r, pattern: 'Access denied*', icase: 1))
{
  set_kb_item(name: 'ftp/'+port+'/denied', value: TRUE);
  ftp_close(socket: soc);
  exit(0, 'FTP server on port '+ port + ' is closed');
}

foreach cmd (make_list("HELP", "USER ftp"))
# Not QUIT, as some servers close the connection without a 2xx code
{
 send(socket: soc, data: cmd + '\r\n');
 r = ftp_recv_line(socket: soc, retry: 3);

 # Avoid FP on FTPS
 if (r =~ "^550[ -]SSL/TLS required")
 {
   set_kb_item(name: 'ftp/'+port+'/TLS', value: TRUE);
   set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);# Temporary
   close(soc);
   exit(0, "This is an FTPS server");
 }

 if (r !~ '[1-5][0-9][0-9][ -]')
 {
   debug_print('FTP server on port ', port, ' answer to ', cmd, ': ', r);
   security_note(port: port);
   set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
   close(soc);
   exit(0);
 }
 debug_print(level:2, 'FTP server on port ', port, ' answer to ', cmd, ': ', r);
}

close(soc);
