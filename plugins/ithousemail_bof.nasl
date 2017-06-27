#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10455);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2000-0488");
 script_bugtraq_id(1285);
 script_osvdb_id(354);

 script_name(english:"ITHouse Mail Server v1.04 To: Field Handling Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server is ITHouse Mail Server. Versions 1.04 or 
earlier of this server are vulnerable to a buffer overrun which 
happens during the delivery routine of the mails if an attacker has
sent a message with a too long 'To:' field.

An attacker may use this flaw to execute arbitrary
code on this host.

*** Note : we could not check the version number of
*** the server, so this item may be a false positive." );
 # https://web.archive.org/web/20000819133105/http://archives.neohapsis.com/archives/win2ksecadvice/2000-q2/0148.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5e98581" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for the latest software release." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/01");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks if the remote smtp server is ITHouse Mail Server"); 
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 
 script_family(english:"SMTP problems");
 
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if(get_port_state(port))
{
 data = get_smtp_banner(port:port);
 if(!data)exit(0);
 if(egrep(string:data,
 	 pattern:".*IT House Mail Server.*"))
	 	security_hole(port);
}
