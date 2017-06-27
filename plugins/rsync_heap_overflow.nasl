#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11943);
 script_version ("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/01/15 21:39:12 $");

 script_cve_id("CVE-2003-0962");
 script_bugtraq_id(9153);
 script_osvdb_id(2898);
 script_xref(name:"RHSA", value:"2003:398-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:050");
 
 script_name(english:"rsync < 2.5.7 Unspecified Remote Heap Overflow");
 script_summary(english:"Determines if rsync is running.");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote rsync server is affected by a heap buffer overflow
condition when running in server mode. An attacker can exploit this
issue to gain a shell on the host and execute arbitrary code.

Note that since rsync does not advertise its version number and since
there are few details about this flaw at this time, this might be a
false positive.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to rsync version 2.5.7");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/04");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/12/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsyncd", 873);
 exit(0);
}

port = get_kb_item("Services/rsyncd");
if(!port)port = 873;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("rsyncd/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}




#
# rsyncd speaking protocol 26 or older *MIGHT* be vulnerable
#

if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-6])[^0-9]", string:welcome))
{
 security_hole(port);
}
