#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description)
{
  script_id(13849);
  script_version("$Revision: 1.21 $");
 
  script_name(english:"Horde Chora Software Detection");
  script_summary(english:"Checks for the presence of Chora");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains web-based interface to CVS
repositories." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Chora, a PHP-based interface to CVS
repositories from the Horde Project." );
 script_set_attribute(attribute:"see_also", value:"http://www.horde.org/chora/" );
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/28");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");
  script_family(english:"CGI abuses");

  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/horde");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Horde is a prerequisite.
horde_install = get_kb_item(string("www/", port, "/horde"));
if (isnull(horde_install)) exit(0, "The 'www/"+port+"/horde' KB item is missing.");
matches = eregmatch(string:horde_install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(1);
horde_dir = matches[2];


# Search for version number in a couple of different pages.
files = make_list(
  "/horde/services/help/?module=chora&show=menu",
  "/horde/services/help/?module=chora&show=about",
  "/cvs.php"
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/chora", horde_dir+"/chora", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  # If it looks like Chora...
  if (
    '<title>Version Control ::' >< res ||
    'services/help/?module=chora' >< res ||
    'Chora: Copyright 2000' >< res ||
    'css.php?app=chora"' >< res
  )
  {
    version = NULL;

    foreach file (files)
    {
      # Get the page.
      if ("/services/help" >< file) url = horde_dir + file;
      else url = dir + file;

      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

      # Specify pattern used to identify version string.
      #
      # - version 3.x
      if ("show=menu" >< file)
      {
        pat = ">Chora H[0-9]+ \(([0-9]+\.[^<]+)\)</span>";
      }
      # - version 2.x
      else if ("show=about" >< file)
      {
        pat = '>This is Chora +(.+).<';
      }
      # - version 1.x
      else if (file =~ "^/cvs.php")
      {
        pat = 'class=.+>CHORA +(.+)</a>';
      }
      # - someone updated files but forgot to add a pattern???
      else
      {
        debug_print("Don't know how to handle file '", file, "'!\n");
        exit(1);
      }

      # Get the version string.
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            version = item[1];
            break;
          }
        }
      }

      # If the version is known...
      if (!isnull(version))
      {
        if (dir == "") dir = "/";
        set_kb_item(
          name:string("www/", port, "/chora"), 
          value:string(version, " under ", dir)
        );
	set_kb_item(name:"www/chora", value:TRUE);
        if (installs[version]) installs[version] += ';' + dir;
        else installs[version] = dir;

        break;
      }
    }
  }
  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (max_index(keys(installs)) && !thorough_tests) break;
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';
        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Chora was';
    else report += 's of Chora were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
