#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18156);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1397");
  script_bugtraq_id(13405);
  script_osvdb_id(15866);

  script_name(english:"PHP-Calendar includes/search.php Multiple Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running PHP-Calendar, a web-based calendar
written in PHP. 

The version of PHP-Calendar installed on the remote host suffers from
a SQL injection vulnerability due to its failure to sanitize input to
the 'sort' and 'order' parameters to the 'includes/search.php' script. 
An attacker can exploit this flaw to alter database queries,
potentially revealing sensitive information or even modifying data." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=323483" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-Calendar version 0.10.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/26");
 script_cvs_date("$Date: 2012/08/28 22:35:49 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:php-calendar:php-calendar");
 script_end_attributes();
 
  summary["english"] = "Checks for SQL injection vulnerability in PHP-Calendar search.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Try the exploit.
foreach dir (cgi_dirs()) {
  postdata = string(
    "submit=Submit&",
    "searchstring=nessus&",
    "action=search&",
    "sday=1&",
    "smonth=1&",
    "syear=2005&",
    "eday=31&",
    "emonth=12&",
    "eyear=2005&",
    # values for both these fields are passed as-is to MySQL; the
    # single quote will cause a syntax error in affected versions.
    "sort=startdate&",
    "order='", SCRIPT_NAME
  );
  r = http_send_recv3(method: "POST", port:port, item: dir + "/index.php",
      content_type: "application/x-www-form-urlencoded",
      data: postdata );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see a syntax error.
  if (
    egrep(
      string:res, 
      pattern:string("an error in your SQL syntax.+ near ''", SCRIPT_NAME, "'"), 
      icase:TRUE
    )
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
