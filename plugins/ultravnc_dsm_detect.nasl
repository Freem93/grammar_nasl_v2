#
# (C) Tenable Network Security, Inc.
#

# MA 2007-07-27: three new plugins have been released. They now use a random IV


include("compat.inc");

if(description)
{
 script_id(19289);
 script_version ("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");
 
 script_name(english: "UltraVNC w/ DSM Plugin Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote control service is running on this port." );
 script_set_attribute(attribute:"description", value:
"UltraVNC seems to be running on the remote port. 

Upon connection, the remote service on this port always sends the same
12 pseudo-random bytes. 

It is probably UltraVNC with the old DSM encryption plugin.  This
plugin tunnels the RFB protocol into a RC4-encrypted stream. 

This old protocol does not use a random IV so the RC4 pseudo random
flow is reused from one session to another.  An authenticated user
could leverage this issue to decrypt other users' sessions." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port.  Otherwise, upgrade UltraVNC and use one of the new and
safer plugins which implement a random IV." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/24");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Detect 12 pseudo-random bytes in banner (UltraVNC w/ old DSM)");
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl", "vnc.nasl");
 script_require_ports("Services/unknown", 5900);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("dump.inc");

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
 port = get_unknown_svc(5900);
 if (! port) exit(0);
}
else port = 5900;

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

b = get_kb_banner(port: port, type: 'spontaneous');
if (strlen(b) != 12) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);

r1 = recv(socket: s, length: 512);
if (strlen(r1) != 12) exit(0);

send(socket: s, data: '012345678901');
r = recv(socket: s, length: 512);

# Let this test here: cleartext VNC answers to my silly "request"
if (strlen(r) > 0) exit(0);

close(s);

s = open_sock_tcp(port);
if (! s) exit(0);

r2 = recv(socket: s, length: 512);
if (r2 != r1) exit(0);

close(s);

# I'm not sure about that and I don't have an old version of the plugin
# if (strlen(r) == 0) exit(0);

# aka statistical test, because I'm paranoid

total = 0;
all_ascii = TRUE;

for (i = 0; i < 12; i ++)
{
# z = ord(r[i]);
 z = ord(r1[i]);
 if (z < 9 || z > 126) all_ascii = 0;

 for (j = 1; j < 256; j *= 2)
  if (z & j) total ++;
}

if (all_ascii && report_paranoia < 1) exit(0);

if (total >= 24 && total <= 72)
{
 register_service(port: port, proto: 'ultravnc-dsm');
 if (report_verbosity > 1)
 {
   security_warning(port: port, 
     extra: '\nThe received data is :\n\n', hexdump(ddata: r1));
 }
 else
   security_warning(port: port);
}
