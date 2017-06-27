#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18539);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2033", "CVE-2005-2034");
  script_bugtraq_id(14000, 14002);
  script_osvdb_id(17400, 17401);

  script_name(english:"i-Gallery <= 3.3 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is susceptible
to multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running i-Gallery, a web-based photo gallery from
Blue-Collar Productions. 

The installed version of i-Gallery fails to sanitize user-supplied
input before using it as a folder name in several scripts.  An
unauthenticated attacker can exploit this flaw to access files and
folders outside i-Gallery's main gallery folder and to conduct
cross-site scripting attacks against visitors to the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/402880/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/20");
 script_cvs_date("$Date: 2014/05/21 20:41:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:blue-collar_productions:i-gallery");
script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in i-Gallery <= 3.3");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the directory traversal flaw.
  w = http_send_recv3(method:"GET", item:string(dir, "/folderview.asp?folder=.."), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we can see anything in the parent directory.
  if (
    egrep(
      string:res, 
      # nb: 'i' is for the filename, 'f' the folder.
      pattern:"viewphoto\.asp?i=[^&]+&f=\.\."
    )
  ) { 
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
