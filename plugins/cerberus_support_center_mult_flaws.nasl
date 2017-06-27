#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20347);
  script_version("$Revision: 1.24 $");

  script_cve_id("CVE-2005-4427", "CVE-2005-4428");
  script_bugtraq_id(16062);
  script_osvdb_id(21988, 21989, 21990, 21991, 21992, 21993, 21994, 21995);

  script_name(english:"Cerberus Support Center Multiple Remote Vulnerabilities (SQLi, XSS)");
  script_summary(english:"Checks for multiple vulnerabilities in Cerberus Support Center");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by SQL
injection and cross-site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cerberus Support Center, a customer support
portal written in PHP. 

The installed version of Cerberus Support Center is affected by a
cross-site scripting flaw due to its failure to sanitize input to the
'kb_ask' parameter of the 'index.php' script before using it in
dynamically-generated web pages.  In addition, it reportedly fails to
sanitize input to the 'file_id' parameter of the 'attachment_send.php'
script before using it in database queries. 

Exploitation of the SQL injection vulnerability requires that an
attacker first authenticate while the cross-site scripting issue may
be possible without authentication, depending on the application's
configuration." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/972" );
 script_set_attribute(attribute:"see_also", value:"http://www.cerberusweb.com/devblog/?p=56" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cerberus Support Center 3.2.0pr2 and edit
'attachment_send.php' as described in the forum post referenced above. 
Note that this does not, though, fix the cross-site scripting issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/20");
 script_cvs_date("$Date: 2017/05/08 18:22:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/support-center", "/support", cgi_dirs()));
else dirs = make_list(cgi_dirs());

# nb: the documentation uses 'support.php' when integrating the product
#     into Cerberus Help Desk, although the actual name is arbitrary.
if (thorough_tests) files = make_list("index.php", "support.php");
else files = make_list("index.php");

foreach dir (dirs) {
  foreach file (files) {
    # Try to exploit the XSS flaw.
    #
    # nb: we're SOL if authentication is required.
    r = http_send_recv3(method:"GET", port: port,
      item:string( dir, "/", file, "?",
        "mod_id=2&",  "kb_ask=", urlencode(str:string("</textarea>", xss))));
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # the result looks like the results of a KB search and...
      '<td class="box_content_text">' >< res &&
      # we see our XSS.
      string("</textarea>", xss) >< res
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
