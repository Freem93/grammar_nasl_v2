#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18670);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2204");
  script_bugtraq_id(14203);
  script_osvdb_id(17809, 17810);

  script_name(english:"SiteMinder 5.5 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by
several cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SiteMinder, an access-management solution
from Netegrity / Computer Associates. 

The installed version of SiteMinder suffers from several cross-site
scripting flaws in its 'smpwservicescgi.exe' and 'login.fcc' scripts.  
An attacker can exploit these flaws to inject arbitrary HTML and 
script code into the browsers of users of the affected application, 
thereby leading to cookie theft, site mis-representation, and similar 
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jul/111");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jul/161");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/08");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2002/10/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in SiteMinder";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
exss = urlencode(str:xss);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Check whether the script exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/smpwservicescgi.exe"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (egrep(string: r[2], pattern:'img alt="Logo" src=".+/siteminder_logo\\.gif')) {
    # Try to exploit one of the flaws.
    postdata = string(
      "SMAUTHREASON=0&",
      "TARGET=/&",
      "USERNAME=nessus&",
      'PASSWORD=">', exss, "&",
      "BUFFER=endl"
    );
    r = http_send_recv3(method: "POST", item: strcat(dir, "/smpwservicescgi.exe"), port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
 data: postdata);
    if (isnull(r)) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< r[2]) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
