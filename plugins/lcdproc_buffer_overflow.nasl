#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10378);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0295");
 script_bugtraq_id(1131);
 script_osvdb_id(13654);

 script_name(english:"LCDproc < 0.4.1 screen_add Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"A buffer overflow in the remote LCDproc server may allow an attacker
to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote LCDproc service is vulnerable to a buffer overflow attack
when processing commands received from the network due to a lack of
bound checks. 

An attacker may exploit this flaw to execute arbitrary code on the remote host,
with the privileges of the LCDproc process (usually, nobody)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LCDproc 0.4.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/20");
 script_cvs_date("$Date: 2011/03/21 01:44:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"LCDproc version check");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc."); 
 script_family(english:"Gain a shell remotely");
 script_dependencie("lcdproc_detect.nasl");
 script_require_keys("lcdproc/version");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/lcdproc");
if(!port)port = 13666;

version = get_kb_item("lcdproc/version");
if ( ! version ) exit(0);
if ( ereg(pattern:"^0\.([0-3]([^0-9]|$)|4([^0-9.]|$)|4\.0)", string:version) ) security_hole(port);
