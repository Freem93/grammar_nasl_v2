#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11797);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(8131);
 script_osvdb_id(2285, 57067);
 
 script_name(english:"UnrealIRCd OperServ Raw Channel Join DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote chat server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ircd which may crash
when it receives certain raw messages.

An attacker could exploit this flaw to disable this service remotely." );
 script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/12580" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to UnrealIRCD 3.2 beta17 or 3.1.6, as this reportedly fixes
the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/21");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}

#

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

key = string("irc/banner/", port);
banner = get_kb_item(key);
if(!banner)exit(0);

# Unreal ircd
if(egrep(pattern:".*Unreal3\.((1\.[0-5][^0-9])|2-beta([0-9][^0-9]|1[0-6]))", string:banner))
{
 security_warning(port);
 exit(0);
}

# Unreal ircd
if(egrep(pattern:".*Unreal3\.((1\.[0-5][^0-9])|2-beta([0-9][^0-9]|1[0-6]))", string:banner))
{
 security_warning(port);
 exit(0);
}
