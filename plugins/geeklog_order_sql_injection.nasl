#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18622);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/08/15 22:31:39 $");

  script_cve_id("CVE-2005-2152");
  script_bugtraq_id(14143);
  script_osvdb_id(17724);

  script_name(english:"Geeklog User Comment Retrieval SQL Injection");
  script_summary(english:"Checks for user comment retrieval SQL injection vulnerability in Geeklog");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw.");
  script_set_attribute(attribute:"description", value:
"The installed version of Geeklog suffers from a SQL injection
vulnerability due to the application's failure to sanitize user-
supplied input via the 'order' parameter of the 'comment.php' script. 
By leveraging this flaw, an attacker may be able to recover sensitive
information, such as password hashes, launch attacks against the
underlying database, and the like.");
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory-062005.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to Geeklog version 1.3.11 sr1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("geeklog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/geeklog");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw enough to cause a syntax error.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/comment.php?",
      "mode=display&",
      "format=flat&",
      # nb: it's best if this is an unused cid.
      "pid=99999&",
      # nb: this will generate a syntax error since it's invalid 
      #     for an ORDER clause.
      "order=", SCRIPT_NAME
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we get a SQL error.
  if ("A SQL error has occured." >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
