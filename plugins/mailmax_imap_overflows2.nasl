#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Sat, 17 May 2003 14:31:14 +0200 
#  From: 0x36 <release@0x36.org>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer overflow vulnerability found in MailMax version 5


include("compat.inc");

if(description)
{
 script_id(11637);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2003-0319");
 script_bugtraq_id(7327);
 script_osvdb_id(12048);
 
 script_name(english:"MailMax IMAP Server SELECT Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be executed on the remote host using the
remote IMAP server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the MailMax IMAP server which, 
according to its version number, is vulnerable to various overflows which 
may allow an authenticated user to execute arbitrary commands on this 
host or to disable it remotely." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MailMax 5.5 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/11");
 script_cvs_date("$Date: 2011/03/16 13:22:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks the version of the remote IMAP server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

include("imap_func.inc");

port = get_kb_item("Services/imap");
if(!port)port = 143;
banner = get_imap_banner ( port: port );
if ( ! banner ) exit(0);
if(egrep(pattern:"MailMax [1-5][^0-9]", string:banner) ) security_warning(port);
