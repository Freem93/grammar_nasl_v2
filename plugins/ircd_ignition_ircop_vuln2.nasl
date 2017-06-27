#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18291);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2005-1640", "CVE-2005-1641");
 script_bugtraq_id(13656, 13654);
 script_osvdb_id(16625, 16626);
 
 script_name(english:"ignitionServer < 0.3.6-P1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IRC server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the IgnitionServer IRC 
service which contains a bug in the way it handles locked channels, as
well as a design error regarding the access validation checks.

An attacker may use this flaw to block an IRC operator out of a 
protected channel. A host may use this flaw to delete an entry created
by a owner." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b96598ba" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IgnitionServer 0.3.6-P1 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/15");
 script_cvs_date("$Date: 2011/03/21 01:44:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"checks the version of the remote ircd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("ircd.nasl");
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

if(egrep(pattern:".*ignitionServer 0\.([0-2]\.|3\.[0-5][^0-9]|3\.6[^-]).*", string:banner)) 
 security_hole(port);

