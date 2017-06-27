#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(19519);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2005-2869");
  script_bugtraq_id(14674, 14675);
  script_osvdb_id(19048, 19049);

  script_name(english:"phpMyAdmin < 2.6.4 Multiple XSS");
  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in phpMyAdmin < 2.6.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
cross-site scripting vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of phpMyAdmin installed on the
remote host may suffer from two cross-site scripting vulnerabilities
due to its failure to sanitize user input to the 'error' parameter of
the 'error.php' script and in 'libraries/auth/cookie.auth.lib.php'.  A
remote attacker may use these vulnerabilities to cause arbitrary HTML
and script code to be executed in a user's browser within the context
of the affected application." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e8e06c0" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f133bb25" );
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin 2.6.4-rc1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/29");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencie("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];

  if (ver =~ "^([01]\.|2\.([0-5]\.|6\.[0-3]))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
