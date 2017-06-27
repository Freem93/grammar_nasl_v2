#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19308);
  script_version("$Revision: 1.25 $");

  script_bugtraq_id(14391);
  script_osvdb_id(18515);

  script_name(english:"Advanced Guestbook User-Agent Header HTML Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Advanced Guestbook, a free guestbook
written in PHP. 

The installed version of Advanced Guestbook fails to properly sanitize
the 'HTTP_USER_AGENT' environment variable before using it in
dynamically-generated content.  An attacker can exploit this flaw to
launch cross-site scripting attacks against the affected application." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Advanced Guestbook version 2.3.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 script_set_attribute(attribute:"see_also", value:"http://proxy2.de/forum/viewtopic.php?t=4144" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/26");
 script_cvs_date("$Date: 2017/04/25 14:28:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for User-Agent HTML injection vulnerability in Advanced Guestbook";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:string(dir, "/addentry.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like Advanced Guestbook...
  if ('<form method="post" action="addentry.php" name="book"' >< res) {
    # Carbonize's image verification hack (http://carbonize.co.uk/Lazarus/Forum/index.php?topic=31.0)
    # prevents us from using the form programmaticly so, if it's in use,
    # we'll just check the banner instead.
    if ('img src="verifyimage.php?k=' >< res) {
      pat = '>Advanced Guestbook ([^<]+)</font>';
      matches = egrep(string:res, pattern:pat);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(string:match, pattern:pat);
          if (!isnull(ver)) {
            ver = ver[1];
            # nb: 2.3.2 and below are affected.
            if (ver =~ "^([01]\.|2\.([0-2]|3\.[0-2]))") {
              	security_warning(port);
              exit(0);
            }
            break;
          }
        }
      }
    }
    else {
      # Get the verification hash, if it exists.
      pat = '<input type="hidden" name="gb_hash" value="(.+)">';
      matches = egrep(string:res, pattern:pat);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          hash = eregmatch(string:match, pattern:pat);
          if (!isnull(hash)) {
            hash = hash[1];
            break;
          }
        }
      }

      # Try to exploit the flaw.
      postdata = string(
        "gb_name=NESSUS&",
        "gb_comment=Test+from+", SCRIPT_NAME, "&",
        # nb: previewing the results will tell us whether the flaw exists
        #     without actually updating the guestbook.
        "gb_action=Preview"
      );
      if (hash) {
        postdata = string(
          "gb_hash=", hash, "&",
          postdata
        );
      }
      r = http_send_recv3(method:"POST", version:11, item: dir+"/addentry.php", port: port,
      	add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
	data: postdata);
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if we see our XSS.
      if (xss >< res) {
       	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
