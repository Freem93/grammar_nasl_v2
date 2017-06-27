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
 script_id(11088);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2012/04/23 00:46:17 $");

 script_cve_id("CVE-2001-0715");
 script_bugtraq_id(3898);
 script_osvdb_id(9303);
 
 script_name(english:"Sendmail RestrictQueueRun Option Debug Mode Information Disclosure");
 script_summary(english:"Check sendmail version number for 'debug mode leak'");
 
 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to information disclosure.");
 script_set_attribute(attribute:"description", value:
"According to the version number of the remote mail server, 
a local user may be able to obtain the complete mail configuration
and other interesting information about the mail queue even if
he is not allowed to access those information directly, by running

	sendmail -q -d0-nnnn.xxx

where nnnn & xxx are debugging levels.

If users are not allowed to process the queue (which is the default)
then you are not vulnerable. 

This vulnerability is _local_ only.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Sendmail or 
do not allow users to process the queue (RestrictQRun option).");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");

 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#

include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);

banner = get_smtp_banner(port: port);
if(! banner || "Switch-" >< banner ) exit(0);

if(egrep(pattern:"Sendmail.*[^/]8\.(([0-9]\..*)|(1[01]\..*)|(12\.0)).*",
	string:banner))
	security_note(port);
