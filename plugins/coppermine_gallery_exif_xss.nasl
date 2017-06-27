#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19511);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-2676");
  script_bugtraq_id(14625);
  script_osvdb_id(18918);

  script_name(english:"Coppermine Photo Gallery EXIF Data XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Coppermine Gallery installed
on the remote host is prone to cross-site scripting attacks because it
does not sanitize malicious EXIF data stored in image files.  Using a
specially crafted image file, an attacker can exploit this flaw to
cause arbitrary HTML and script code to be executed in a user's
browser within the context of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/372" );
 script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/forum/index.php?topic=20933.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Coppermine Gallery 1.3.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/19");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
  script_summary(english:"Checks version number of Coppermine Gallery");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("coppermine_gallery_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Check the version number.
  if (ver =~ "^(0\.|1\.([0-2]\.|3\.[0-3]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
