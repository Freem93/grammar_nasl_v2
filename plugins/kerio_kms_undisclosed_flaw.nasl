#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15404);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2004-2441");
 script_bugtraq_id(11300);
 script_osvdb_id(10504);

 script_name(english:"Kerio MailServer < 6.0.3 Unspecified Vulnerability");
 script_summary(english:"Checks for Kerio MailServer < 6.0.3");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote mail server has an unspecified vulnerability."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote host is running a version of Kerio MailServer prior to
6.0.3. 

There is an undisclosed flaw in the remote version of this server that
might allow an attacker to execute arbitrary code on the remote host."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.kerio.com/mailserver/history"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to Kerio MailServer 6.0.3 or newer."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2004/09/30"
 );
 script_set_attribute(
  attribute:"patch_publication_date", 
  value:"2004/09/30"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2004/10/01"
 );
 script_cvs_date("$Date: 2012/08/16 22:15:22 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;
banner = get_smtp_banner(port:port);
if ( ! banner) exit(0);
if (egrep(string:banner, pattern:"^220 .* Kerio MailServer ([0-5]\.[0-9]\.[0-9]|6\.0\.[0-2]) ESMTP ready") )
	{
		security_hole(port);
		exit(0);
	}
