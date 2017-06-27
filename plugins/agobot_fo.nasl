#
# (C) Tenable Network Security, Inc.
# 
# 


include("compat.inc");

if(description)
{
 script_id(12128);
 script_version ("$Revision: 1.10 $");
 script_name(english:"Agobot.FO Backdoor Detection");
 script_summary(english:"Determines the presence of Agobot.FO");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a backdoor installed." );
 script_set_attribute(attribute:"description", value:
"The remote host has the Agobot.FO backdoor installed.  This
backdoor is known to:

  - Scan local networks for common Microsoft
    vulnerabilities.

  - Scan local networks for exploitable DameWare systems.

  - Brute force local Microsoft machine User accounts.

  - Connect to an IRC channel and setup a BOT for remote
    command execution.");

 script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/v-descs/agobot_fo.shtml" );
 script_set_attribute(attribute:"solution", value:
"This backdoor should be immediately removed from the network and
manually cleaned." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/04/05");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/agobot.fo");
 exit(0);
}


#
# The code starts here:
#

# This service is detected by find_service2.nasl
port = get_kb_item("Services/agobot.fo");
if ( port ) security_hole(port);
