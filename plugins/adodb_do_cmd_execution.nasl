#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20384);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-0147");
  script_osvdb_id(22291);

  script_name(english:"ADOdb tmssql.php do Parameter Arbitrary PHP Function Execution");
  script_summary(english:"Checks for do parameter command execution vulnerability in ADOdb");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that allows execution of
arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ADOdb, a database abstraction library for
PHP. 

The installed version of ADOdb includes a test script named
'tmssql.php' that fails to sanitize user input to the 'do' parameter
before using it execute PHP code.  An attacker can exploit this issue
to execute arbitrary PHP code on the affected host subject to the
permissions of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-64/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?540d6007" );
 script_set_attribute(attribute:"solution", value:
"Remove the test script or upgrade to ADOdb version 4.70 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/09");
 script_cvs_date("$Date: 2015/10/13 15:19:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "Settings/ThoroughTests");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (!thorough_tests) exit(0, "This plugin only runs if the 'Perofrm thorough tests' setting is enabled.");

port = get_http_port(default:80, php: 1);

subdirs = make_list(
  "/adodb/tests",                      # PHPSupportTickets
  "/lib/adodb/tests",                  # Moodle / TikiWiki
  "/library/adodb/tests",              # dcp_portal
  "/xaradodb/tests"                    # Xaraya
);


# Loop through directories.
foreach dir (cgi_dirs()) {
  foreach subdir (subdirs) {
    # Try to exploit the flaw to display PHP info.
    r = http_send_recv3(method:"GET", port: port, exit_on_fail: 1,
      item:string(
        dir, subdir, "/tmssql.php?",
        "do=phpinfo"));
    res = r[2];

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}

exit(0, "No vulnerable software was found on port "+port+".");
