#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17314);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2005-0774", "CVE-2005-0775", "CVE-2005-0776", "CVE-2005-0777", "CVE-2005-0778", "CVE-2005-1629");
  script_bugtraq_id(12779, 13620);
  script_osvdb_id(14679, 14680, 14681, 14682, 14683, 16731);

  script_name(english:"PhotoPost PHP < 5.0.1 Multiple Remote Vulnerabilities");
  script_summary(english:"Checks for multiple remote vulnerabilities in PhotoPost PHP 5.0 RC3 and older");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PhotoPost PHP installed on the
remote host has several vulnerabilities:

  - An Access Validation Vulnerability.
    The 'adm-photo.php' script fails to verify authentication
    credentials, which allows an attacker to change the 
    properties of thumbnails of uploaded images.

  - A SQL Injection Vulnerability.
    The 'uid' parameter in the 'member.php' script is not 
    properly sanitized before use in SQL queries. An
    attacker can leverage this flaw to disclose or modify
    sensitive information or perhaps even launch attacks
    against the underlying database implementation.

  - A Cross-site Scripting (XSS) Vulnerability.
    The 'editbio' parameter of the user profile form is not sanitized
    properly, allowing an attacker to inject arbitrary script or
    HTML in a user's browser in the context of the affected website, 
    resulting in theft of authentication data or other such attacks." );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/213" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/May/311" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to PhotoPost PHP version 5.01 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/11");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php_pro");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("photopost_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/photopost");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^[0-4].*|5\.0[^0-9]?|5\.0rc[123]$")
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
