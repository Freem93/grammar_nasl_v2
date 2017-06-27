#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19419);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2596");
  script_bugtraq_id(14547);
  script_osvdb_id(18684);

  script_name(english:"Gallery PostNuke Integration Access Validation Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that does not
properly validate access." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gallery, a web-based photo album. 

According to its banner, the version of Gallery installed on the
remote host is subject to an access validation issue when integrated
with PostNuke, as is the case on the remote host.  The issue means
that any user with any level of admin privileges in PostNuke also has
admin privileges in Gallery." );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/index.php?name=PNphpBB2&file=viewtopic&t=7048" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?741ad7ee" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.5.1-RC2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/10");
 script_cvs_date("$Date: 2011/03/14 21:48:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for PostNuke integration access validation vulnerability in Gallery");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("postnuke_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Call up Gallery's main index.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/modules.php?",
      "op=modload&",
      "name=gallery&",
      "file=index"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if the reported version is < 1.5.1-RC2.
  if (egrep(string:res, pattern:"Powered by <a href=.+>Gallery.* v(0\.|1\.([0-4]\.|5\.(0|1-RC1)))")) {
    security_warning(port);
    exit(0);
  }
}
