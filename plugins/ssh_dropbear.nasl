#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11821);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(8439);
 script_osvdb_id(2429);
 
 script_name(english:"Dropbear SSH Server Username Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is runnning Dropbear SSH.

There is a format string vulnerability in all versions of the Dropbear SSH 
server up to and including version 0.34. An attacker may use this flaw to 
execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of the Dropbear SSH server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/08/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/08/18");
 script_cvs_date("$Date: 2011/03/16 13:37:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks remote SSH server type and version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports("Services/ssh", 22);
 script_dependencies("ssh_detect.nasl");
 exit(0);
}

#
# The script code starts here
#

include("backport.inc");
port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(get_backport_banner(banner:banner));

if("dropbear" >< banner)
{
    if (ereg(pattern:"ssh-.*-dropbear_0\.(([0-2].*)|3[0-4])", string:banner))
    {
        security_hole(port);
    }
}
 
