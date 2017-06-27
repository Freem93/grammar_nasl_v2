#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18494);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2041");
  script_bugtraq_id(13964);
  script_osvdb_id(17320, 18919);

  script_name(english:"ViRobot Linux Server addschup Multiple Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is prone to a remote buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ViRobot Linux Server, a commercial anti-
virus product for Linux. 

According to its banner, the installed version of ViRobot Linux Server
suffers from a remote buffer overflow vulnerability in its web-based
management interface.  By passing specially crafted data through the
'ViRobot_ID' and 'ViRobot_PASS' cookies when calling the 'addschup'
CGI script, an unauthenticated attacker may be able to write arbitrary
data to root's crontab entry, thus giving him complete control over
the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?164e1cec" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jun/188" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ef6b0a5" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/14");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for remote buffer overflow vulnerability in ViRobot Linux Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/addschup"), port:port, exit_on_fail: 1);

  # If it looks like the script.
  if ("<font size=2>You need to authenticate.</font>" >< r[2]) {
    # Get the site's index.html -- it has the version number in its title.
    r = http_send_recv3(method:"GET", item:"/index.html", port:port, exit_on_fail: 1);
    res = r[2];

    # There's a problem if the version number is <= 2.0.
    if (
      egrep(
        string:res, 
        pattern:"<title>ViRobot Linux Server Ver ([01]\..*|2\.0)</title>"
      )
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
