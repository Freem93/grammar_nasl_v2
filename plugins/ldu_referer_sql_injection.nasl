#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19774);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-4711");
  script_bugtraq_id(14896);
  script_osvdb_id(19585);

  script_name(english:"Land Down Under HTTP Referer Header SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of Land Down Under fails to sanitize input
passed through the HTTP Referer header before using it in database
queries.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
attacker can exploit this issue to manipulate database queries,
possibly revealing sensitive information or corrupting arbitrary data." );
 script_set_attribute(attribute:"solution", value:
"Enable PHP's 'magic_quotes_gpc' setting." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/21");
 script_cvs_date("$Date: 2011/03/12 01:05:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for HTTP Referer SQL injection vulnerability in Land Down Under");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("ldu_detection.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ldu");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ldu"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  w = http_send_recv3(method:"GET", item:string(dir, "/"), port:port, 
    add_headers:make_array("Referer", "nessus'"+SCRIPT_NAME));
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we get a syntax error
  if (egrep(string:res, pattern:string("^MySQL error : .+ '", SCRIPT_NAME)))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
