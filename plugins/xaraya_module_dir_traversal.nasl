#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20372);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-3929");
  script_bugtraq_id(15623);
  script_osvdb_id(21249);
  script_xref(name:"EDB-ID", value:"1345");

  script_name(english:"Xaraya index.php module Parameter Traversal Arbitrary File/Directory Manipulation");
  script_summary(english:"Checks for module parameter directory traversal vulnerability in Xaraya");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Xaraya installed on the remote host does not sanitize
input to the 'module' parameter of the 'index.php' script before using
it to write to files on the affected host. Using a specially crafted
request, an unauthenticated attacker can create directories and
possibly overwrite arbitrary files on the affected host subject to the
permissions of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/418209/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.xaraya.com/index.php/news/551" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Xaraya 1.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/29");
 script_cvs_date("$Date: 2011/10/04 22:11:52 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("xaraya_detection.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xaraya");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xaraya"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to create a directory under
  # Xaraya's 'var' directory.
  dirname = string(SCRIPT_NAME, "-", unixtime());
  r = http_send_recv3(method: "GET", port: port, 
    item:string(
      dir, "/index.php?",
      "module=../../../../", dirname
    ));
  if (isnull(r)) exit(0);

  # There's a problem if the directory was created.
  #
  # nb: by not tacking on a trailing slash, we'll be able to detect
  #     whether the directory exists even if, say, Apache's autoindex
  #     feature is disabled.
  r = http_send_recv3(method: "GET", item:string(dir, "/var/", dirname), port:port);
  if (egrep(pattern:"^HTTP/.* 301 Moved", string:r[0])) {
    security_warning(port);
    exit(0);
  }
}
