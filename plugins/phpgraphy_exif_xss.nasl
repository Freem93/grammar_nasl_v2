#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19514);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2005-2735");
  script_bugtraq_id(14669);
  script_osvdb_id(19014);

  script_name(english:"phpGraphy EXIF Data XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpGraphy, a web-based photo album. 

According to its banner, the version of phpGraphy installed on the
remote host is prone to script insertion attacks because it does not
sanitize malicious EXIF data stored in image files.  Using a
specially crafted image file, an attacker can exploit this flaw to
cause arbitrary HTML and script code to be executed in a user's
browser within the context of the affected application." );
  # http://web.archive.org/web/20090208140316/http://cedri.cc/advisories/EXIF_XSS.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb13daf6" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/372" );
 script_set_attribute(attribute:"solution", value:
"While we are unaware of any public statement from the project,
upgrading to phpGraphy 0.9.10 or later reportedly addresses the
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/25");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgraphy:phpgraphy");
script_end_attributes();

 
  summary["english"] = "Checks for EXIF data script insertion vulnerability in phpGraphy";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php: 1);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Look for phpGraphy's main page.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # Check the version number.
  if (
    'site is using <a href="http://phpgraphy.sourceforge.net/">phpGraphy</a>' >< res &&
    egrep(string:res, pattern:"[^0-9.]0\.([0-8]\..*|9\.[0-9][^0-9]*) - Page generated")
  ) {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
