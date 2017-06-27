#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35322);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 
 script_name(english:'HTTP Backdoor Detection');
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be compromised." );
 script_set_attribute(attribute:"description", value:
"Regardless of the request that's made, the remote web server returns a
Microsoft executable.  This is highly suspicious and may be indication
of a worm.  For example, the Conficker.A / Downadup worm is known to
propagate in this fashion." );
 script_set_attribute(attribute:"solution", value:
"Check the host and disinfect / reinstall it if necessary." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: 'Identifies MS executable file format in the web server output');
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("httpver.nasl", "find_service1.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("dump.inc");

function is_exe(banner)
{
 local_var	len, h;

 len = strlen(banner);
 if (len < 40) return 0;
 h = substr(banner, 0, 1);
 if (h != 'MZ' && h != 'ZM') return 0;
 if ('This program cannot be run in DOS mode' >< banner ||
     'This program must be run under Win32' >< banner ||
     '\x50\x45\x00\x00' >< banner) return 1;
 return 0;
}

# NB: we want to look at "broken" web servers.
port = get_kb_item("Services/www");
if (! port) exit(0);

# We use get_unknown_banner because the information is cached in the KB
# 1. This reduces the network traffic and speeds up the whole scan;
# 2. Those fake web servers appear to be very unreliable, so it is better 
#    to use information that we already have. A new connection may fail.
# Note that the content of the HTTP cache cannot be fully used, as there 
# is a \0 after MZ and the KB truncates the string at this level.

bv = get_unknown_banner2(port: port, dontfetch: 0);
if (isnull(bv)) exit(0);
banner = bv[0]; type = bv[1];
if (type != 'get_http')
{
  r = http_send_recv3(port: port, method: 'GET', item: '/');
  if (isnull(r)) exit(0);
  banner = r[1]+'\r\n'+r[2];
}
if ('\r\nMZ' >!< banner && '\r\nZM' >!< banner) exit(0);

i = stridx(banner, '\r\n\r\n');
if (i < 0 ) exit(0);
exe = substr(banner, i + 4);
if (! is_exe(banner: exe)) exit(0);

r = http_send_recv3(port: port, method: 'GET', item: strcat('/', rand_str(), '.html'));
if (! isnull(r))
{
  exe = r[2];
  if (! is_exe(banner: exe)) exit(0);
  extra = strcat('HTTP headers :\n', r[1], '\n');
}

if (strlen(exe) > 0)
{
 sha1 = hexstr(SHA1(exe));
 extra = strcat('Payload :\n\n', hexdump(ddata: substr(exe, 0, 0x3FF)), '\n');
 extra = strcat(extra,
'\nThis may be a known malware.\nGo to http://www.virustotal.com/buscaHash.html and enter\n-> ', sha1, '\n');
 if (experimental_scripts)
   set_kb_item(name: '/tmp/antivirus/TCP/'+port, value: hexstr(exe));
}
if (report_verbosity > 0) security_hole(port:port, extra: '\n'+extra);
else security_hole(port);
declare_broken_web_server(port: port, reason:
 "The web server distributes malware EXE files only");
