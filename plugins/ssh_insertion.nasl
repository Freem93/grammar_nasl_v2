#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10268);
 script_version ("$Revision: 1.35 $");
 script_cvs_date("$Date: 2015/07/10 14:11:56 $");
 script_cve_id("CVE-1999-1085");
 script_osvdb_id(212);
 
 script_name(english:"SSH CBC/CFB Data Stream Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server contains a cryptographical weakness that might allow
a third party to decrypt the traffic." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of SSH that is older than (or as old as) 
version 1.2.23.

The remote version of this software is vulnerable to a known plaintext attack,
which could allow an attacker to insert encrypted packets in the client - server
stream that will be deciphered by the server, thus allowing the attacker to 
execute arbitrary commands on the remote server" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.2.25 of SSH which solves this problem." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/07/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/06/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc");
port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = get_backport_banner(banner:banner);

if ( "openssh" >< tolower(banner) ) exit(0);

if(ereg(pattern:"^SSH-.*-1\.2(\.([0-9]|1[0-9]|2[0123])|)$", string:banner))
	security_warning(port);
