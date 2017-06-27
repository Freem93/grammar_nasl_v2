#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11058);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");

 script_cve_id("CVE-1999-0626");
 script_osvdb_id(856);

 script_name(english:"RPC rusers Remote Information Disclosure");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate logged in users.");
 script_set_attribute(attribute:"description", value:
"The rusersd RPC service is running.  It provides an attacker
interesting information such as how often the system is being used, the
names of the users, and more.");
 script_set_attribute(attribute:"solution", value:"Disable this service if not needed.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"1990/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
 script_family(english:"RPC");

 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("sunrpc_func.inc");


RPC_PROG = 100002;
RUSERSPROC_NAME = 0x02;

port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);

if (! port) exit(0);
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp (port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

 udp = TRUE;

 data = NULL;

 packet = rpc_packet (prog:RPC_PROG, vers:2, proc:RUSERSPROC_NAME, data:data, udp:udp);

 data = rpc_sendrecv (socket:soc, packet:packet, udp:udp);
 if (isnull(data) || (strlen(data) < 4))
   exit(0);

 register_stream(s:data);

 users = xdr_getdword();
 report = NULL;

 for (i=0; i<users; i++)
 {
  term = xdr_getstring();
  user = xdr_getstring();
  disp = xdr_getstring();

  xdr_getdword();
  xdr_getdword();

  report += string (user, " (", term, ") from ", disp, "\n");
 }

 if (report)
 {
  report = string (
		"Using rusers, we could determine that the following users are logged in :\n\n",
		report
		);
  security_warning(port:port, proto:"udp", extra:report);
 }
 else
  security_warning(port:port, proto:"udp", extra:report);
