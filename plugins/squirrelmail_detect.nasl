#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)



include("compat.inc");

if (description)
{
  script_id(12647);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");
 
  script_name(english:"SquirrelMail Detection");
  script_summary(english:"Checks for SquirrelMail");
  
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a webmail application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SquirrelMail, a PHP-based webmail package
that provides access to mail accounts via POP3 or IMAP." );
 script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
script_end_attributes();

 
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for version in a couple of different pages.
files = make_list(
  "/src/login.php", 
  "/src/compose.php", 
  "/ChangeLog", 
  "/ReleaseNotes"
);


# Search for SquirrelMail.
if (thorough_tests) dirs = list_uniq(make_list("/squirrelmail", "/webmail", "/mail", "/sm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  url = string(dir, "/src/login.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  if (
    !egrep(pattern:"<title>Squirrel[mM]ail - Login</title>", string:res) &&
    'onLoad="squirrelmail_loginpage_onload();">' >!< res
  ) continue;

  foreach file (files)
  {
    if (file != "/src/login.php")
    {
      # Get the page.
      url = string(dir, file);
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if (isnull(res)) exit(0);
    }

    # Specify pattern used to identify version string.
    if (file == "/src/login.php" || file == "/src/compose.php") {
      pat = "<SMALL>SquirrelMail version (.+)<BR";
    }
    else if (file == "/ChangeLog") {
      pat = "^Version (.+) - [0-9]";
    }
    # nb: this first appeared in 1.2.0 and isn't always accurate.
    else if (file == "/ReleaseNotes") {
      pat = "Release Notes: SquirrelMail (.+) *\*";
    }
    # - someone updated files but forgot to add a pattern???
    else {
      exit(1, strcat("do not know how to handle file '", file, "'"));
    }

    # Get the version string.
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match, icase:TRUE);
        if (item == NULL) break;
        ver = item[1];

        # Success!
        if (dir == "") dir = "/";
        set_kb_item(
          name:string("www/", port, "/squirrelmail"),
          value:string(ver, " under ", dir)
        );
	set_kb_item(name:"www/squirrelmail", value: TRUE);
        if (installs[ver]) installs[ver] += ';' + dir;
        else installs[ver] = dir;

        # nb: only worried about the first match.
        break;
      }
    }
    # nb: if we found an installation, stop iterating through files.
    if (max_index(keys(installs))) break;
  }
  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (max_index(keys(installs)) && !thorough_tests) break;
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity)
  {
    info = "";
    n = 0;
    foreach ver (sort(keys(installs)))
    {
      info += '  Version : ' + ver + '\n';
      foreach dir (sort(split(installs[ver], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Squirrelmail was';
    else report += 's of Squirrelmail were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
