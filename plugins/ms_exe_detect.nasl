#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33950);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2015/09/24 21:17:12 $");
 
 script_name(english: "MS Executable Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be compromised." );
 script_set_attribute(attribute:"description", value:
"This service is unknown to Nessus.  It appears to send a Microsoft
Windows executable when a connection to it is established.  This may
be evidence of some malware that are known to propagate in this
manner." );
 script_set_attribute(attribute:"solution", value:
"Check the host and disinfect / reinstall it if necessary." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"malware", value:"true"); 
script_end_attributes();

 
 script_summary(english: "Identifies MS executable file format in the data flow");
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 script_exclude_keys("global_settings/disable_service_discovery");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("dump.inc");

if (get_kb_item("global_settings/disable_service_discovery")) exit(0);

port = get_unknown_svc();
if (! port) exit(0);

bv = get_unknown_banner2(port: port, dontfetch: 1);
if (! isnull(bv))
{
 banner = bv[0]; type = bv[1];
 if (strlen(banner) > 40 && substr(banner, 0, 1) == 'MZ' && 
     ('This program cannot be run in DOS mode' >< banner ||
      'This program must be run under Win32' >< banner ||
      '\x50\x45\x00\x00' >< banner))
 {
  register_service(port:port, proto:"malware-distribution");

  exe = '';
  soc = open_sock_tcp(port);
  if (soc)
  {
   if (type == 'get_http')
    send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
   else if (type == 'help')
    send(socket: soc, data: 'HELP\r\n');
   r = recv(socket: soc, length: 8192);
   if (substr(r, 0, 1) == 'MZ')
    while (strlen(r) > 0)
    {
      exe = strcat(exe, r);
      r = recv(socket: soc, length: 8192);
    }
   close(soc);
  }
  extra = strcat('Type : ', type, '\nBanner :\n', 
  	hexdump(ddata: substr(banner, 0, 0x3FF)) );
  if (strlen(exe) > 0)
  {
    md5 = hexstr(MD5(exe));
    sha1 = hexstr(SHA1(exe));
    extra = strcat(extra,
'\nThis may be a known malware.\n',
'Go to http://www.virustotal.com/buscaHash.html and enter\n-> ', sha1);
   security_hole(port:port, extra: extra);
#   if (experimental_scripts)
#     set_kb_item(name: '/tmp/antivirus/TCP/'+port, value: hexstr(exe));
  }
  exit(0);
 }
}
