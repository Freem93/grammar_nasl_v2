#
# (C) Tenable Network Security, Inc.
#

# Ref:
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: sendmail -bt negative index bug...
# From: Michal Zalewski <lcamtuf@DIONE.IDS.PL>
# Date: Sun, 8 Oct 2000 15:12:46 +0200 
#


include("compat.inc");

if (description)
{
 script_id(10809);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");

 script_osvdb_id(676);
 
 script_name(english:"Sendmail < 8.11.2 -bt Option Local Overflow");
 script_summary(english:"Checks the version number"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is reportedly affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
vulnerable to a '-bt' overflow attack that allows a local user to
execute arbitrary commands as root.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Oct/120");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/12");
 script_set_attribute(attribute:"solution", value:"Upgrade to Sendmail version 8.11.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");

 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if ( report_paranoia > 1 ) exit(0);


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);

banner = get_smtp_banner(port: port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:"Sendmail.*([^/](8\.(([0-9]\..*)|(10\..*)|(11\.[01])))|SMI-8\.).*",
	string:banner))
 	security_hole(port);
}
