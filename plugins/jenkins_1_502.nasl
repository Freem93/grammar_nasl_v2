#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65056);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id(
    "CVE-2013-0327",
    "CVE-2013-0328",
    "CVE-2013-0329",
    "CVE-2013-0330",
    "CVE-2013-0331"
  );
  script_bugtraq_id(58454, 58456, 58721, 58722, 58726);
  script_osvdb_id(90313, 90314, 90315, 90316, 90317);

  script_name(english:"Jenkins < 1.502 / 1.480.3 and Jenkins Enterprise 1.447.x / 1.466.x / 1.480.x < 1.447.7.1 / 1.466.13.1 / 1.480.3.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Jenkins version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a job scheduling / management system that
is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts a version of Jenkins or Jenkins Enterprise
that is affected by multiple vulnerabilities :

  - An unspecified cross-site scripting vulnerability.
   (CVE-2013-0328)

  - Multiple unspecified cross-site request forgery
    vulnerabilities. (CVE-2013-0327, CVE-2013-0329)

  - An unspecified denial of service vulnerability.
    (CVE-2013-0331)

  - An unspecified security bypass vulnerability exists
    that could allow an attacker to build otherwise
    restricted jobs. (CVE-2013-0330)"
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2013-02-16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?874c7641");
  # http://www.cloudbees.com/jenkins-advisory/jenkins-security-advisory-2013-02-16.cb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb7cfe44");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.502 / 1.480.3, Jenkins Enterprise 1.447.7.1 /
1.466.13.1 / 1.480.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/Jenkins");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

get_kb_item_or_exit("www/Jenkins/"+port+"/Installed");

# Check if install is Enterprise
enterprise_installed = get_kb_item("www/Jenkins/"+port+"/enterprise/Installed");
if (!isnull(enterprise_installed)) appname = "Jenkins Enterprise by CloudBees";
else appname = "Jenkins Open Source";

url = build_url(qs:'/', port:port);

version = get_kb_item_or_exit("www/Jenkins/"+port+"/JenkinsVersion");
if (version == "unknown") audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);
if (report_paranoia < 2 && isnull(enterprise_installed)) audit(AUDIT_PARANOID);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
if (max_index(ver) < 2) exit(0, "The version information of the "+appname+" install at "+url+" is not granular enough.");

if (
  report_paranoia > 1 && isnull(enterprise_installed) &&
  (
    ver_compare(ver:version, fix:'1.480.3', strict:FALSE) == -1 || # LTS version
    (
      ver[0] == 1 && ver[1] > 480 && ver[1] < 502 &&  # flag vulnerable major version releases,
      max_index(ver) < 3                              # but not future LTS releases
    )
  )
)
{
  vuln  = TRUE;
  fixed = "1.502 / 1.480.3";
}

# Check Enterprise ranges
if (
  enterprise_installed &&
  (
    # All previous
    (ver[0] < 1 || (ver[0] == 1 && ver[1] < 447))
    ||
    # 1.447.x < 1.447.7.1
    (ver[0] == 1 && ver[1] == 447 && (ver[2] < 7 || (ver[2] == 7 && ver[3] < 1)))
    ||
    # 1.466.x < 1.466.13.1
    (ver[0] == 1 && ver[1] == 466 && (ver[2] < 13 || (ver[2] == 13 && ver[3] < 1)))
    ||
    # 1.480.x < 1.480.3.1
    (ver[0] == 1 && ver[1] == 480 && (ver[2] < 3 || (ver[2] == 3 && ver[3] < 1)))
  )
)
{
  vuln  = TRUE;
  fixed = "1.447.7.1 / 1.466.13.1 / 1.480.3.1";
}

if (vuln)
{
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Product           : ' + appname +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
