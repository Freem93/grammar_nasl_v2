#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20348);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-4427", "CVE-2005-4428");
  script_bugtraq_id(16062);
  script_osvdb_id(
    21988, 
    21989, 
    21990, 
    21991, 
    21992, 
    21993, 
    21994, 
    21995
  );

  script_name(english:"Cerberus Helpdesk GUI Agent < 2.7.1 Multiple Remote Vulnerabilities (SQLi, XSS)");
  script_summary(english:"Checks for multiple vulnerabilities in Cerberus Helpdesk GUI Agent < 2.7.1");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by
multiple SQL injection and cross-site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cerberus Helpdesk, a web-based helpdesk
suite written in PHP. 

The installed version of Cerberus Helpdesk is affected by several SQL
injection issues and one cross-site scripting flaw because of its
failure to sanitize user-supplied input to various parameters and
scripts before using it in database queries and in dynamically-
generated HTML.  Successful exploitation of these issues requires that
an attacker first authenticate." );
  # 
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b22b720" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cerberus GUI Agent version 2.7.1 when it becomes available." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/20");
 script_cvs_date("$Date: 2015/02/02 19:32:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberus:cerberus_helpdesk");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cerberus", "/cerberus-gui", "/helpdesk", "/tickets", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Get the login page.
  r = http_send_recv3(method:"GET", item:string(dir, "/login.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # Exploitation requires authentication so the best we can do is a banner check.
  if (egrep(pattern:'class="cer_footer_text">Cerberus Helpdesk .+ Version ([01]\\..+|2\\.([0-6]\\..*|7\\.0)) Release<br>', string:res)) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
