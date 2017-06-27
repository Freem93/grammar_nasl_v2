#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20011);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-4792");
  script_bugtraq_id(15088);
  script_osvdb_id(17788);

  script_name(english:"phpWebSite index.php Search Module SQL Injection");
  script_summary(english:"Detects search module SQL injection vulnerability in phpWebSite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpWebSite that fails to
sanitize user-supplied input to the 'module' parameter of the 'search'
module before using it in database queries.  An attacker may be able to
exploit this issue to obtain sensitive information such as user names
and password hashes or to launch attacks against the database." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Oct/320");
 script_set_attribute(attribute:"see_also", value:"https://github.com/AppStateESS/phpwebsite");
 script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor's advisory or upgrade
to phpWebSite 0.10.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/07");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebsite:phpwebsite");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("phpwebsite_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpwebsite");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit the flaw.
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "module=", urlencode(str:string("' UNION SELECT 1,'", SCRIPT_NAME, "'--"))
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our script name in the search block title.
  if (egrep(pattern:string('^ +<td class=".+"><b>.+ ', SCRIPT_NAME, "</b></td>"), string:res)) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }

  # The exploit requires that PHP's 'magic_quotes_gpc' setting be disabled
  # so check the version number as long as report paranoia is paranoid.
  if (ver =~ "^0\.([0-9]\.|10\.[01]$)" && report_paranoia > 1) {
    w = string(
      "Nessus has determined the vulnerability exists on the remote\n",
      "host simply by looking at the version number of phpWebSite\n",
      "installed there.\n"
    );
    security_hole(port:port, extra: w);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
