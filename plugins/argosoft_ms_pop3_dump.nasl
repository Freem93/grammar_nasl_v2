#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20976);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-0928");
  script_bugtraq_id(16808);
  script_osvdb_id(23475);

  script_name(english:"ArGoSoft Mail Server _DUMP Command System Information Disclosure");
  script_summary(english:"Checks for _DUMP command information disclosure vulnerability in ArGoSoft POP3 server");

 script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is subject to an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ArGoSoft Mail Server, a messaging system
for Windows. 

An unauthenticated attacker can gain information about the installed
application as well as the remote host itself by sending the '_DUMP'
command to the POP3 server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Feb/447" );
 script_set_attribute(attribute:"see_also", value:"http://www.argosoft.com/rootpages/mailserver/ChangeList.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft Mail Server 1.8.8.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/16");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/pop3", 110);
  exit(0);
}


include("global_settings.inc");
include("pop3_func.inc");
include("misc_func.inc");


port = get_service(svc: "pop3", default: 110, exit_on_fail: 1);

if (get_kb_item("pop3/"+port+"/false_pop3")) exit(0);


# Make sure the banner is from ArGoSoft.
banner = get_pop3_banner(port:port);
if (!banner || "+OK ArGoSoft Mail Server" >!< banner) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);


# Try to exploit the flaw.
send(socket:soc, data: '_DUMP\r\n');
n = 0;
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s);
  if (!isnull(m)) {
    resp = m[1];
    if ("-ERR" >< resp) break;
  }
  else if (s == ".") break;
  else info += s + '\n';
  n ++;
  if ( n > 200 ) break;
}


# There's a problem if we got a response.
if (info) {
  if (report_verbosity > 1)
    security_warning(port:port, extra: info);
  else
    security_warning(port:port);
}


# Clean up.
close(soc);
