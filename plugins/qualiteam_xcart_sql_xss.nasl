#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(18419);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/01/14 20:12:26 $");

  script_cve_id("CVE-2005-1822", "CVE-2005-1823");
  script_bugtraq_id(13817);
  script_osvdb_id(
    16936,
    16937,
    16938,
    16939,
    16940,
    16941,
    16942,
    16943,
    16944,
    16945,
    16946,
    16947,
    16948,
    16949,
    16950,
    16951
  );

  script_name(english:"Qualiteam X-Cart Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in X-Cart");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by several
flaws." );
  script_set_attribute(attribute:"description", value:
"The remote host is running X-Cart, a PHP-based shopping cart system. 

The version installed on the remote host suffers from numerous SQL
injection and cross-site scripting vulnerabilities.  Attackers can
exploit the former to influence database queries, resulting possibly
in a compromise of the affected application, disclosure of sensitive
data, or even attacks against the underlying database.  And
exploitation of the cross-site scripting flaws can be used to steal
cookie-based authentication credentials and perform similar attacks." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/401035/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/06");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);

init_cookiejar();
erase_http_cookie(name: "xid");

# For each CGI directory...
foreach dir (cgi_dirs())
{
  # Try to exploit one of the SQL flaws.
  r = http_send_recv3(method: "GET",
    item:string(dir, "/help.php?section='", SCRIPT_NAME),
    port:port,
    exit_on_fail:TRUE
  );

  # If ...
  if (
    # it looks like X-Cart and...
    ! isnull(get_http_cookie(name: "xid")) &&
    egrep(string: r[2], pattern:"^<!-- /?central space -->") &&
    # we get a syntax error.
    egrep(string: r[2], pattern:string("SELECT pageid FROM xcart_stats_pages WHERE page='/cart/help\.php\?section='", SCRIPT_NAME))
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
