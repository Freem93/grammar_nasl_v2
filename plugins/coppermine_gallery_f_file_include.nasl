#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20984);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0873");
  script_bugtraq_id(16718);
  script_osvdb_id(23347);

  script_name(english:"Coppermine Photo Gallery showdoc.php f Parameter Local File Inclusion");
  script_summary(english:"Checks for f parameter remote file include vulnerability in Coppermine Photo Gallery");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of Coppermine Photo Gallery fails to sanitize
user input to the 'f' parameter in the 'docs/showdoc.php' script
before using it in a PHP 'include()' function.  An unauthenticated
attacker may be able to exploit this flaw to view arbitrary files or
to execute arbitrary PHP code, possibly taken from third-party hosts. 

Note that successful exploitation either requires that the remote host
be running Windows or that it have some type of Samba share." );
 # https://web.archive.org/web/20060418091554/http://retrogod.altervista.org/cpg_143_adv.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e51ca68" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425387/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/forum/index.php?topic=28062.0" );
 script_set_attribute(attribute:"solution", value:
"Patch the affected script as recommended in the vendor advisory
referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/17");
 script_cvs_date("$Date: 2017/05/11 13:46:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

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
  dir = matches[2];

  # Try to exploit the flaw to read a file in the directory.
  #
  # nb: the vendor patch always displays 'index.htm' so the caller
  #     can't request another file.
  file = 'COPYING';
  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/docs/showdoc.php?",
      "f=", file));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if it looks like the GPL.
  if ("GNU GENERAL PUBLIC LICENSE" >< res) {
    security_warning(port);
    exit(0);
  }
}

