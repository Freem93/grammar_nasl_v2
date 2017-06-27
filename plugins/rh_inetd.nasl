#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE

include("compat.inc");

if (description)
{
  script_id(11006);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2014/05/26 15:47:04 $");

  script_cve_id("CVE-2001-0309");
  script_bugtraq_id(2395);
  script_osvdb_id(6019);

  script_name(english:"Red Hat 6.2 inetd Internal Service Connections Remote DoS");
  script_summary(english:"Stalls the remote inetd");

  script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
  script_set_attribute(attribute:"description", value:
"The remote host has a bug in its 'inetd' server. 'inetd' is the
'internet super-server' and is in charge of managing multiple
sub-servers (like telnet, ftp, chargen, and more).

There is a bug in the inetd server that comes with RedHat 6.2, which
allows an attacker to prevent it from working completely by forcing it
to consume system resources.");
  script_set_attribute(attribute:"solution", value:"Upgrade to inetd-0.16-7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(7, 9, 13, 19, 23, 37);
  script_timeout(0);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("telnet_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

do_check = 0; #thorough_tests;

  ret[0] = 0;
  n = 0;

  if(get_port_state(7))
  {
    soc = open_sock_tcp(7);
    if(soc){
      close(soc);
      ret[n] = 7;
      n = n + 1;
    }
  }

  if(get_port_state(9))
  {
    soc = open_sock_tcp(9);
    if(soc){
      close(soc);
      ret[n] = 9;
      n = n + 1;
    }
  }

  if(get_port_state(13))
  {
    soc = open_sock_tcp(13);
    if(soc){
      close(soc);
      ret[n] = 13;
      n = n + 1;
    }
  }

  if(get_port_state(19))
  {
    soc = open_sock_tcp(19);
    if(soc){
      close(soc);
      ret[n] = 19;
      n = n + 1;
    }
  }
  if(get_port_state(37))
  {
    soc = open_sock_tcp(37);
    if(soc){
      close(soc);
      ret[n] = 37;
      n = n + 1;
    }
  }

if(!n)exit(0);


if(!do_check)
{
 port = get_kb_item("Services/telnet");
 if(!port) port = 23;

 if(!get_port_state(port))exit(0);
 buf = get_telnet_banner(port: port);
 if (buf)
 {
  if("Red Hat Linux release 6.2" >< buf)
  {
   security_warning(port:23, extra: "

*** As the banner was used to determine this vulnerability,
*** this might be a false positive");
  }
 }
 exit(0);
}




for(i=0;i<1500;i=i+n)
{
 #
 # We *must* sleep 3 seconds between each connection,
 # or else inetd will close the port
 #
  sleep(3);
  for(j=0;j<n;j=j+1)
  {
  soc = open_sock_tcp(ret[j]);

  if(!(ret[j] == 9))
  {
   send(socket:soc, data:'foo\r\n');
   r = recv(socket:soc, length:5);
   if(!r){
   	security_warning(ret[j]);
	exit(0);
	}
  }
  close(soc);
  }
}
