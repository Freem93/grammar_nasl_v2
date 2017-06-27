#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11938);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2003-1215", "CVE-2003-1216");
 script_bugtraq_id(9122, 9314);
 script_osvdb_id(2875, 3302);
 
 script_name(english:"phpBB < 2.0.7 Multiple Script SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB older than 2.0.7.

There is a flaw in the remote software that could allow anyone to inject
arbitrary SQL commands, which may in turn be used to gain administrative
access on the remote host or to obtain the MD5 hash of the password of 
any user." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/12/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/27");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

 
 script_summary(english:"SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpBB");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([01]\..*|2\.0\.[0-6]([^0-9]|$))", string:version) )
{
	security_hole ( port );
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

