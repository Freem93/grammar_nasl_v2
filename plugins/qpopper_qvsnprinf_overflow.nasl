#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11376);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2003-0143");
 script_bugtraq_id(7058);
 script_osvdb_id(9794);
 script_xref(name:"SuSE", value:"SUSE-SA:2003:018");
 
 script_name(english: "Qpopper pop_msg() Macroname Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Qpopper server, according to its banner, is vulnerable to a 
one-byte overflow ih its pop_msg function after a call to Qvsnprintf(). 

An attacker may use this flaw to execute code with the privileges of the
Qpopper service (usually non-root), provided that he has a valid POP 
account to log in with.

*** This test could not confirm the existence of the
*** problem - it relied on the banner being returned." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.0.5cf2 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/10");
 script_cvs_date("$Date: 2011/03/11 21:52:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Qpopper options buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("popserver_detect.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner)
{
    if(get_port_state(port))
    {
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
    }
}

if(banner)
{
    if(ereg(pattern:".*Qpopper.*version 4\.0\.[0-4][^0-9].*", string:banner, icase:TRUE))
    {
	security_warning(port);
    }
}
exit(0);
