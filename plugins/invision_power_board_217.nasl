#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(22089);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-7071");
  script_bugtraq_id(18984);
  script_osvdb_id(27352);
  script_xref(name:"EDB-ID", value:"2010");

  script_name(english:"Invision Power Board classes/class_session.php CLIENT_IP HTTP Header SQL Injection");
  script_summary(english:"Checks version of IPB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the installation of Invision Power Board on
the remote host reportedly fails to sanitize input to the 'CLIENT_IP'
HTTP request header before using it in database queries.  An
unauthenticated attacker may be able to leverage this issue to
disclose sensitive information, modify data, or launch attacks against
the underlying database. 

Note that it's unclear whether successful exploitation depends on any
PHP settings, such as 'magic_quotes'." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Power Board 2.1.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/14");
 script_cvs_date("$Date: 2012/07/18 00:20:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(pattern:"^(.+) under (/.*)$", string:install);
if (!isnull(matches))
{
  ver = matches[1];

  if (ver && ver =~ "^([01]\.|2\.(0\.|1\.[0-6][^0-9]?))")
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
