#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14613);
 script_version("$Revision: 1.22 $");
 script_cve_id("CVE-2004-1651");
 script_bugtraq_id(11080);
 script_osvdb_id(9450, 9451);
 
 script_name(english:"phpScheduleIt 1.0.0 RC1 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of phpScheduleIt on the remote
host is earlier than 1.0.0.  Such versions are vulnerable to HTML
injection issues.  For example, an attacker may add malicious HTML and
JavaScript code in a schedule page if he has the right to edit the
'Schedule Name' field.  This field is not properly sanitized.  The
malicious code would be executed by a victim web browser displaying
this schedule." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/420" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/235" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpScheduleIt version 1.0.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/31");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:brickhost:phpscheduleit");
script_end_attributes();

 script_summary(english:"Checks version of phpScheduleIt");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("phpscheduleit_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/phpscheduleit");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Check an install.
install = get_kb_item(string("www/", port, "/phpscheduleit"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];

  if (ereg(pattern:"^(0\..*|1\.0\.0 RC1)", string:ver))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
