#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19513);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-2737");
  script_bugtraq_id(14671);
  script_osvdb_id(19017);

  script_name(english:"PhotoPost PHP Pro EXIF Data XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PhotoPost PHP Pro installed on
the remote web server is prone to script insertion attacks because it does
not sanitize malicious EXIF data stored in image files.  Using a
specially crafted image file, an attacker can exploit this flaw to
cause arbitrary HTML and script code to be executed in a user's
browser within the context of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://cedri.cc/advisories/EXIF_XSS.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/372" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/25");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:photopost:photopost_php_pro");
 script_end_attributes();

 
  summary["english"] = "Checks for EXIF data script insertion vulnerability in PhotoPost PHP Pro";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("photopost_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/photopost");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-4]\.|5\.(0|1($|\.0)))")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
