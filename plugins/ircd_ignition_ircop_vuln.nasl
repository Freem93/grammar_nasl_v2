#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14388);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-2553");
 script_bugtraq_id(9783);
 script_osvdb_id(4121);
 
 script_name(english:"ignitionServer umode Command Global Operator Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote instant messaging server is affected by a privilege
escalation issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the IgnitionServer IRC service
which might be vulnerable to a flaw that lets a remote attacker gain
elevated privileges on the system.  A local IRC operator can supply an
unofficial command to the server to obtain elevated privileges and
become a global IRC operator." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7503de28" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IgnitionServer 0.2.1-BRC1 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/05");
 script_cvs_date("$Date: 2011/12/09 19:21:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#the code

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

if(egrep(pattern:".*ignitionServer 0\.([01]\.|2\.0).*", string:banner)) 
{
 security_warning(port);
 exit(0);
}

