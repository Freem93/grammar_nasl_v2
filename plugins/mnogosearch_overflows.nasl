#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(11735);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2003-0436", "CVE-2003-0437");
  script_bugtraq_id (7865, 7866);
  script_osvdb_id(11872, 11873);

  script_name(english:"mnoGoSearch search.cgi Multiple Parameter Remote Overflows");
  script_summary(english:"Checks for search.cgi");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A CGI script hosted on the remote web server is affected by multiple
buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The mnoGoSearch search.cgi CGI is installed on the remote web server. 
Older versions of this software have multiple buffer overflow
vulnerabilities.  A remote attacker could exploit these issues to
execute arbitrary code. 

Note that Nessus only detected the presence of this CGI, and did not
attempt to determine whether or not it is vulnerable."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Disable this CGI if it is not being used, or upgrade to version 
3.1.21 / 3.2.11 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mnogosearch:mnogosearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("mnogosearch_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mnogosearch", "Settings/ParanoidReport");

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "mnogosearch",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
ver = install["ver"];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Ensure to only flag Unix installs using search.cgi (affected versions)
# Version info is available starting in 3.3.x and these versions are not
# affected, so ensure to not flag these.
if (dir =~ "search\.cgi" && ver == UNKNOWN_VER)
{
  security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "mnoGoSearch", build_url(qs:dir, port:port));
