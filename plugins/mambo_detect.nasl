#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(17672);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Mambo Detection");
  script_summary(english:"Checks for presence of Mambo / Mambo Open Source / Mambo CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Mambo, a content management system written
in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.mamboserver.com/content/view/137/104/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/01");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
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
include("audit.inc");
include("install_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Search through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/mambo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

# nb: Mambo has changed a lot over the years and can be configured to look
#     quite different. And getting an accurate version number requires
#     logging in as the administrator. Together, these make this script
#     rather convoluted. Suggestions for improvement welcome.
installs = make_array();
foreach dir (dirs)
{
  type = NULL;
  ver = NULL;

  # Try to pull up administrator page. As long as it exists,
  # it's an easy way to distinguish which Mambo is installed.
  #
  # nb: a few webmasters rename the directory to improve security so
  #     we can't don't assume anything if the page isn't found.
  r = http_send_recv3(method: "GET", item:string(dir, "/administrator/index.php"), port:port);
  if (isnull(r)) exit(0);

  # The title should identify which type of Mambo the site is running.
  if (egrep(string: r[2], pattern:"^<title>.+ - Administration \[Mambo\]</title>$", icase:TRUE))
    type = "mos";
  else if (egrep(string: r[2], pattern:"^<TITLE>.+ \|\| Mambo CMS Admin</TITLE>$", icase:TRUE))
    type = "cms";

  # Sometimes the version number's embeded in the initial administrator
  # page itself; if so, we're done!
  if (!isnull(type))
  {
    pat = "<td .+Version *: *([^<]+)</td>";
    matches = egrep(pattern:pat, string:r[2], icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match, icase:TRUE);
        if (!isnull(item))
        {
          ver = item[1];
          break;
        }
      }
    }
  }

  # If we don't know the version yet...
  if (isnull(ver))
  {
    init_cookiejar();
    # Try to pull up main page.
    r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
    if (isnull(r)) exit(0);

    # If it exists...
    if (r[0] =~ "^HTTP/.* 200 OK")
    {
      # If the type is still unknown...
      if (isnull(type))
      {
        # It's Mambo CMS if...
        # the Generator meta tag says it is.
        if (egrep(string:r[1], pattern:"^X-Meta-Generator: Mambo CMS"))
        {
          type = "cms";
        }
        # else it's Mambo if...
        else if (
          # The mosvisitor cookie is present (only present if stats are enabled) or ...
	  get_http_cookie(name: "mosvisitor") || # == "1"
          # A meta tag says its Mambo or...
          egrep(string: r[1], pattern:"^X-Meta-Description: Mambo( Open Source)? - the dynamic", icase:TRUE) ||
          egrep(string: r[1], pattern:"^X-Meta-Generator: Mambo (\(C\)|- Copyright)", icase:TRUE) ||
          # It has a "Powered by Mambo" logo.
          egrep(string: r[2], pattern:'<img src="images/[^"]+"[^>]* alt="Powered by Mambo', icase:TRUE)
        )
        {
          type = "mos";
        }
        # else it might be Mambo if...
        else if (
          # There are relative links using Mambo components.
          egrep(string: r[2], pattern:'<a href="index2?\\.php\\?option=[^&]+&(Itemid|task)=', icase:TRUE) ||
          egrep(string: r[2], pattern:'<a href="index2?\\.php\\?option=com_(contact|content|frontpage|search|weblinks)', icase:TRUE) ||
          # There are absolute links using search-engine friendly format.
          egrep(
            string: r[2],
            pattern:string(
              '<a href="https?://',
              "[^/]*",
              get_host_name(),
              "[^/]*",
              dir, "(content/(section|view)|component/option,com_)"
            ),
            icase:TRUE
          )
        )
        {
          # So let's try some other checks to make sure.
          #
          # - mambojavascript.js exists in Mambo Open Source 4.5+
          r = http_send_recv3(method: "GET", item:string(dir, "/includes/js/mambojavascript.js"), port:port);
          if (isnull(r)) exit(0);
          if (egrep(string: r[2], pattern:"^\* @package Mambo(Open Source|_[0-9])", icase:TRUE))
          {
            type = "mos";
          }
          else
          {
            # - mambositeserver.gif exists in Mambo Open Source 4.0.x
            #   aka Mambo Site Server.
            r = http_send_recv3(method: "GET", item:string(dir, "/images/stories/mambositeserver.gif"), port:port);
            if (isnull(r)) exit(0);
	    res2 = r[2];
            if (res2[0] == 'G' && res2[1] == 'I' && res2[2] == 'F')
            {
              type = "mos";
            }
          }
        }
      }

      # If we know the type now, try to get the version number.
      if (!isnull(type))
      {
        # Sometimes the version number is part of the Generator meta tag.
        pat = '^X-Meta-Generator: Mambo (CMS|Site Server|Open Source) (.+)';
        matches = egrep(pattern:pat, string: r[1], icase:TRUE);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = eregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[2];
              break;
            }
          }
        }
      }
    }
  }

  # If the type is known, update the KB.
  if (!isnull(type))
  {
    # If we couldn't find the version number, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";

    set_kb_item(
      # nb: keys are identified by "mambo_cms" or "mambo_mos" at the end.
      name:string("www/", port, "/mambo_", type),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name: "www/mambo_"+type, value: TRUE);
    types[dir] = type;
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
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

        if (types[dir] == "cms") type = "CMS ";
        else if (types[dir] == "mos") type = "Mambo Open Source";
        else type = "unknown";

        register_install(
          app_name:"Mambo",
          path:url,
          version:ver,
          extra:make_array("Variant", type),
          port:port);

        info += '  Variant : ' + type + '\n' +
                '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Mambo was';
    else report += 's of Mambo were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
