#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25821);
 script_version ("$Revision: 1.11 $");
 script_cvs_date("$Date: 2017/01/05 15:38:09 $");
 
 script_name(english: "UltraVNC w/ DSM Plugin Detection (2)");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote control service is running on this port." );
 script_set_attribute(attribute:"description", value:
"UltraVNC seems to be running on the remote port. 

Upon connection, the remote service on this port sends pseudo-random
bytes. 

It is probably UltraVNC with the new DSM encryption plugin.  This
plugin tunnels the RFB protocol into a RC4 or AES encrypted stream." );
 script_set_attribute(attribute:"see_also", value:"http://www.ultravnc.com/" );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/31");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Detect pseudo-random bytes in banner (UltraVNC w/ DSM)");
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl", "vnc.nasl");
 script_require_ports("Services/unknown", 5900);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("dump.inc");

# Banner is 44 bytes long for ARC4 or AESv2, 39 bytes long for MSRC4 (UltraVNC 1.0.3)
# Banner is 23 bytes (UltraVNC 1.0.2)

function length_is_ok(len)
{
 local_var r;
 r = (len == 23 || len == 39 || len == 44);
 return r;
}

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
 port = get_unknown_svc(5900);
 if (! port) exit(0);
}
else port = 5900;

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

b = get_kb_banner(port: port, type: 'spontaneous');
len = strlen(b);
if (! COMMAND_LINE && ! length_is_ok(len: len)) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
r1 = recv(socket: s, length: 512);

# Should have been picked by vnc.nasl or find_service*
if (preg(string: r1, pattern: '^RFB +[0-9]+\\.[0-9]+\n$', icase: 0, multiline: 1))
{
 debug_print('Cleartext VNC banner on port ', port, '\n');
 register_service(port: port, proto: 'vnc');
 exit(0);
}

len = strlen(r1);
if (! length_is_ok(len: len))
{
 debug_print('Bad length ', len); 
 exit(0);
}

send(socket: s, data: '012345678901');
r = recv(socket: s, length: 512);
close(s);

if (debug_level > 0)
{
 t = strcat("Data received on ", get_host_ip(), ':', port);
 dump(ddata: r1, dtitle: t);
 dump(ddata: r, dtitle: t);
}

# Let this test here: cleartext VNC answers to my silly "request"
if (strlen(r) > 0) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
r2 = recv(socket: s, length: 512);
if (r2 == r1) exit(0);
#send(socket: s, data: r2);
#r = recv(socket: s, length: 512);
close(s);
if (debug_level > 0)
{
 dump(ddata: r2, dtitle: t);
# dump(ddata: r, dtitle: t);
}

#if (strlen(r) == 0) exit(0);

# aka statistical test, because I'm paranoid

total = 0;
all_ascii = TRUE;
min = len * 2;
max = len * 6;
for (i = 0; i < len; i ++)
{
 z = ord(r1[i]);
 if (z < 9 || z > 126) all_ascii = 0;
#if (z == 0 || z > 127) all_ascii = 0;
 for (j = 1; j < 256; j *= 2)
  if (z & j) total ++;
}

debug_print('port=', port, '- all_ascii=', all_ascii, ' - min=', min, ' - max=', max, ' - total=', total, '\n');

if (all_ascii)
{
 debug_print('Banner is in ASCII characters\n');
 if (report_paranoia < 1) exit(0);
}

if (total >= min && total <= max)
{
 security_note(port: port);
 register_service(port: port, proto: 'ultravnc-dsm');
}
# Else statistical test failed
