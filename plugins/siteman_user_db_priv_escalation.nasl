#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16216);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-0305");
  script_bugtraq_id(12304, 12558);
  script_osvdb_id(13131, 13811);

  script_name(english:"Siteman < 1.1.11 Multiple Vulnerabilities");
  script_summary(english:"Checks Siteman's version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
privilege escalation vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running Siteman, a web-based content management
system written in PHP. 

The version of this software hosted on the remote web server fails to
sanitize input to the 'line' parameter of the 'users.php' script when
'do=create', which allows an attacker with valid credentials to create
an arbitrary administrative user."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2005/Jan/245"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://marc.info/?l=bugtraq&m=110643320814371&w=2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Siteman 1.1.11 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/19");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/20");
 script_cvs_date("$Date: 2016/12/14 20:22:12 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  script_require_keys("www/PHP");
  exit(0);
}

#the code

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, php:TRUE);

foreach dir ( cgi_dirs() )
{
  w = http_send_recv3(method:"GET", item:dir + "/forum.php", port:port, exit_on_fail:TRUE);
  r = w[2];

if( r && '<meta name="generator" content="Siteman ' >< r )
{
  line = egrep(pattern:'<meta name="generator" content="Siteman (0\\.|1\\.(0|1\\.([0-9][^0-9]|10[^0-9])))', string:r);
  if ( line ) 
  {
  security_warning(port);
  exit(0);
  }
 }
}
