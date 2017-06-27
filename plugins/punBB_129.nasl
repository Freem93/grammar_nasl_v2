#
# (C) Tenable Network Security
# 


include("compat.inc");

if (description) {
  script_id(20013);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-3518");
  script_bugtraq_id(15114);
  script_osvdb_id(20018);

  script_name(english:"PunBB search.php old_searches Parameter SQL Injection");
  script_summary(english:"Checks for old_searches parameter SQL injection vulnerability in PunBB");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The version of PunBB installed on the remote host fails to sanitize
user-supplied input to the 'old_searches' parameter of the
'search.php' script before using it in database queries.  Provided
PHP's 'register_globals' setting is enabled, an attacker may be able
to exploit this issue to delete arbitrary data or launch attacks
against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/413481" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB 1.2.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/14");
 script_cvs_date("$Date: 2012/12/17 23:26:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:punbb:punbb");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/punBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  #
  # nb: the exploit only works if the search returns results.
  r = http_send_recv3(method:"GET", port: port, 
    item:string(
      dir, "/search.php?",
      "action=search&",
      "keywords=&",
      # nb: ensure we get a result.
      "author=*&",
      "forum=-1&",
      "search_in=all&",
      "sort_by=0&",
      "sort_dir=DESC&",
      "show_as=topics&",
      "search=Submit&",
      # nb: this will just give us a syntax error. 
      "old_searches[]='", SCRIPT_NAME));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an error claiming punBB can't delete the search results.
  if ("Unable to delete search results" >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
