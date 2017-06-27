#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20841);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"MyBB Detection");
  script_summary(english:"Checks for the presence of MyBB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a bulletin board system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running MyBB (formerly known as MyBulletinBoard), a
web-based bulletin board system written in PHP utilizing MySQL for its
back-end storage.");
  script_set_attribute(attribute:"see_also", value:"http://www.mybb.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
port = get_http_port(default:80, php: TRUE);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mybb", "/forum", "/forums", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs)
{
  # check member.php instead of index.php to avoid flagging any mybb subdirs as separate mybb installs
  res = http_send_recv3(
    method       : 'GET',
    item         : dir + "/member.php?action=login",
    port         : port,
    exit_on_fail : TRUE
  );

  # If it's MyBB.
  if (egrep(pattern:'<[^>]+>My(BB|BulletinBoard)(</| )', string:res[2]))
  {
    # Try to identify the version number from the footer
    #
    # nb: don't put much trust in this -- the vendor habitually
    #     releases patches that do not update the version number.
    ver = UNKNOWN_VER;

    pat = '<[^>]+>My(BB|BulletinBoard)(</a>)? ([0-9][^<]+)(<br />|</a>)';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          ver = item[3];
          break;
        }
      }
    }

    register_install(
      app_name : app,
      path     : dir,
      port     : port,
      version  : ver,
      cpe      : "cpe:/a:mybb:mybb",
      webapp   : TRUE
    );
    installs++;
    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
