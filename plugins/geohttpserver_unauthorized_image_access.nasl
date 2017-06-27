#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18220);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-1552");
  script_bugtraq_id(13571);
  script_osvdb_id(16340);

  name["english"] = "GeoHttpServer Unauthorized Image Access Vulnerability";
  script_name(english:name["english"]);
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server does not properly restrict access to files." );
  script_set_attribute(attribute:"description", value:
"The GeoVision Digital Surveillance System installed on the remote host
suffers from a vulnerability that enables anyone to bypass
authentication and view JPEG images stored on the server by calling
them directly." );
  # http://web.archive.org/web/20050528080136/http://www.esqo.com/research/advisories/2005/100505-1.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01a30bef" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/105" );
  script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/09");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  summary["english"] = "Checks for unauthorized image access vulnerability in GeoHttpServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure the server both is from GeoVision and tries to authenticate access.
res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if (
  egrep(string:res, pattern:"^Server: GeoHttpServer") &&
  egrep(string:res, pattern:'<input type="password"')
) {
  # Check for the vulnerability by trying to request up to 16 different images.
  for (i=1; i<=16; i++) {
    w = http_send_recv3(method:"GET", item:string("/cam", i, ".jpg"), port:port, exit_on_fail: 1);
    res = w[2];

    # Check whether the result is a JPEG.
    if (
      (res[0] == 0xff && res[1] == 0xd8) ||
      "JFIF" >< res
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
