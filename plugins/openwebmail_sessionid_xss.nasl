#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19769);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-2863");
  script_bugtraq_id(14771);
  script_osvdb_id(19225);

  script_name(english:"Open WebMail sessionid Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script which is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of Open WebMail on the remote host is prone to
cross-site scripting attacks because it fails to sanitize user-
supplied input to the 'sessionid' parameter of the
'openwebmail-main.pl' script." );
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/409692/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/03");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for sessionid parameter cross-site scripting vulnerability in Open WebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencie("openwebmail_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/openwebmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # A simple alert.
  xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
  exss = urlencode(str:xss);

  # Try to exploit the flaw.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/openwebmail-main.pl?",
      'sessionid=">', exss
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we see our XSS.
  if (xss >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
