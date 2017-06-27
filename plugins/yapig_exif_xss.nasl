#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19515);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/01 20:05:52 $");

  script_cve_id("CVE-2005-2736", "CVE-2005-4799", "CVE-2006-4421");
  script_bugtraq_id(14670, 15092, 15095, 19709, 23814, 47698);
  script_osvdb_id(19016, 19958, 19959, 29298);

  script_name(english:"YaPiG <= 0.9.5b Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in YaPiG <= 0.9.5b");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
code injection and cross-site scripting attacks." );
  script_set_attribute(attribute:"description", value:
"The remote host is running YaPiG, a web-based image gallery written in
PHP. 

According to its banner, the version of YaPiG installed on the remote
host is prone to arbitrary PHP code injection and cross-site scripting
attacks." );
  script_set_attribute(attribute:"see_also", value:"http://cedri.cc/advisories/EXIF_XSS.txt" );
  script_set_attribute(attribute:"see_also", value:"http://www.seclab.tuwien.ac.at/advisories/TUVSA-0510-001.txt" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Aug/482" );
  script_set_attribute(attribute:"solution", value:
"Remove the software as it is no longer maintained." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/27");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/25");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0, php: 1);

if (thorough_tests) dirs = list_uniq(make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Pull up the main page.
  res = http_get_cache(item:string(dir, "/"), port:port, exit_on_fail: 1);

  # Check the version number of YaPiG.
  if (
    egrep(
      string:res, 
      pattern:"Powered by <a href=.+>YaPiG.* V0\.([0-8][0-9]($|[^0-9])|9([0-4]|5[.ab]))"
    )
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
