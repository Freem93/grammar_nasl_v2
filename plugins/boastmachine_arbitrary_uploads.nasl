#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18247);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1580");
  script_bugtraq_id(13600);
  script_osvdb_id(16334);

  script_name(english:"boastMachine users.inc.php File Extension Validation Arbitrary File Upload");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
arbitrary file upload vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running boastMachine, an open source publishing
tool written in PHP. 

According to its banner, the version of boastMachine installed on the
remote host allows authenticated users to upload arbitrary files and
then run them subject to the privileges of the web server user." );
  # http://web.archive.org/web/20111124002906/http://www.kernelpanik.org/docs/kernelpanik/bmachines.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34547ad7" );
 script_set_attribute(attribute:"see_also", value:"http://boastology.com/pages/changes.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to boastMachine version 3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/11");
 script_cvs_date("$Date: 2013/01/18 23:00:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:boastmachine:boastmachine");
script_end_attributes();

 
  summary["english"] = "Checks for remote arbitrary file upload vulnerability in boastMachine";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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

# Search for boastMachine.
foreach dir (cgi_dirs()) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # Check the banner.
  if (
    # v3.x banners.
    res =~ "Powered by.*http://boastology.com.*v3\.0 platinum" ||
    # v2.x banners span several lines.
    (
      res =~ 'by <a href="http://boastology.com".+>BoastMachine</font></a>' &&
      res =~ "^  v [0-2]\.[0-9]+  <br>$"
    )
  ) {
    security_warning(port);
    exit(0);
  }
}
