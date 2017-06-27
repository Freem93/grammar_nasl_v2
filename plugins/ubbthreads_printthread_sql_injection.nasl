#
# (C) Tenable Network Security
#
# 


include("compat.inc");

if (description) {
  script_id(18098);
  script_version("$Revision: 1.15 $");

  script_cve_id(
    "CVE-2005-1199", 
    "CVE-2005-2057",
    "CVE-2005-2058",
    "CVE-2005-2059",
    "CVE-2005-2060",
    "CVE-2005-2061"
  );
  script_bugtraq_id(13253, 14050, 14052, 14053, 14055);
  script_osvdb_id(
    15698,
    17512,
    17513,
    17514,
    17515,
    17516,
    17517,
    17518,
    17519,
    17520,
    17521,
    17525,
    17526,
    17527,
    17528,
    17529,
    17530,
    17531,
    17532,
    17533
  );

  name["english"] = "UBB.threads < 6.5.2 beta Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
numerous vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of UBB.threads that suffers from
multiple vulnerabilities due to insufficient input validation - local
file inclusion, HTTP response splitting, SQL injection, and cross-site
scripting.  These flaws may allow an attacker to completely compromise
the affected installation of UBB.threads." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/396222" );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00084-06232005" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to UBB.threads 6.5.2 beta or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/19");

 script_cvs_date("$Date: 2015/02/13 21:07:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in UBB.threads < 6.5.2 beta";
  script_summary(english:summary["english"]);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("ubbthreads_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ubbthreads");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # 6.5.1.1 and below are vulnerable.
  if (safe_checks()) {
    if (ver =~ "^([0-5]\.|6\.([0-4][^0-9]|5$|5\.0|5\.1(\.1)?))") {
      report = string(
        "Note that Nessus has determined the vulnerability exists on the\n",
        "remote host simply by looking at the version number of UBB.threads\n",
        "installed there."
      );

      security_hole(port:port, extra:report);
    }
  }
  # Otherwise...
  else {
    # Get a list of existing boards on the target.
    r = http_send_recv3(method:"GET", item:string(dir, "/ubbthreads.php"), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # Loop through a couple of forums...
    i = 0;
    pat = dir + '/postlist.php\\?.*Board=([^"&]+)">';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      board = eregmatch(pattern:pat, string:match);
      if (isnull(board) || ++i > 5) break;

      # Try a simple exploit.
      board = board[1];
      r = http_send_recv3(method:"GET", port: port,
        item:string(
          dir, "/printthread.php?",
          "Board=", board, "&",
          "type=post&",
          # nb: this should just produce a syntax error.
          "main='", SCRIPT_NAME ));
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if we see a syntax error.
      if (egrep(string:res, pattern:string("SQL Error:.+ near '", SCRIPT_NAME, "'"), icase:TRUE)) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
