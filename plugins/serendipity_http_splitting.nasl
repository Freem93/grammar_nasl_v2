#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15543);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2004-1620");
 script_bugtraq_id(11497);
 script_osvdb_id(11013, 11038, 11039);

 script_name(english:"Serendipity Multiple Script HTTP Response Splitting");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote version of Serendipity is affected by an HTTP response-
splitting vulnerability that may allow an attacker to perform a cross-
site scripting attack against the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/230" );
 script_set_attribute(attribute:"see_also", value:"http://www.s9y.org/5.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity 0.7rc1 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/21");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:s9y:serendipity");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of Serendipity");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("serendipity_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/serendipity");
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


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "0\.([0-6][^0-9]|7-b)")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
