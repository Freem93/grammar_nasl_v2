#
# (C) Tenable Network Security, Inc.
#

# References:
# From: "Michal Zalewski" <lcamtuf@echelon.pl>
# To: bugtraq@securityfocus.com
# CC: sendmail-security@sendmail.org
# Subject: RAZOR advisory: multiple Sendmail vulnerabilities

include("compat.inc");

if (description)
{
 script_id(11087);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2012/06/28 19:20:02 $");

 script_cve_id("CVE-2001-0714");
 script_bugtraq_id(3378);
 script_osvdb_id(9302);
 
 script_name(english:"Sendmail < 8.12.1 RestrictQueueRun Option Multiple Argument Local DoS");
 script_summary(english:"Checks the version number for 'queue destruction'");

 script_set_attribute(attribute:"synopsis", value:"The remote mail server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, might be
vulnerable to a queue destruction when a local user runs

	sendmail -q -h1000

If your system does not allow users to process the queue (which is the
default), you are not vulnerable. 

Note that this vulnerability is _local_ only.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail 8.12.1 or later. As a workaround, do not allow users to 
process the queue (RestrictQRun option).");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc."); 
 script_family(english:"SMTP problems");

 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);
if(! banner || "Switch-" >< banner ) exit(0);

if(egrep(pattern:"Sendmail.*[^/]8\.(([0-9]\..*)|(1[01]\..*)|(12\.0)).*",
	string:banner))
	security_note(port);
