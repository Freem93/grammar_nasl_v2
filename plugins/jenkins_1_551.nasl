#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72685);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id(
    "CVE-2013-5573",
    "CVE-2013-7285",
    "CVE-2013-7330",
    "CVE-2014-2058",
    "CVE-2014-2060",
    "CVE-2014-2061",
    "CVE-2014-2062",
    "CVE-2014-2063",
    "CVE-2014-2064",
    "CVE-2014-2065",
    "CVE-2014-2066",
    "CVE-2014-2068"
  );
  script_bugtraq_id(
    64414,
    64760,
    65694,
    65718,
    65720
  );
  script_osvdb_id(
    101187,
    102253,
    103401,
    103402,
    103403,
    103404,
    103405,
    103406,
    103407,
    103409,
    103410,
    103410
  );

  script_name(english:"Jenkins < 1.551 / 1.532.2 and Jenkins Enterprise 1.509.x / 1.532.x < 1.509.5.1 / 1.532.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

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

  - A flaw in the default markup formatter allows cross-site
    scripting via the Description field in the user
    configuration. (CVE-2013-5573)

  - A security bypass vulnerability allows remote
    authenticated attackers to change configurations and
    execute arbitrary jobs. (CVE-2013-7285, CVE-2013-7330,
    CVE-2014-2058)

  - An unspecified flaw in the Winstone servlet allows
    remote attackers to hijack sessions. (CVE-2014-2060)

  - An input control flaw in 'PasswordParameterDefinition'
    allows remote attackers to disclose sensitive
    information including passwords. (CVE-2014-2061)

  - A security bypass vulnerability due to API tokens not
    being invalidated when a user is deleted.
    (CVE-2014-2062)

  - An unspecified flaw allows remote attackers to conduct
    clickjacking attacks. (CVE-2014-2063)

  - An information disclosure vulnerability in the
    'loadUserByUsername' function allows remote attackers
    to determine whether a user exists via vectors related
    to failed login attempts. (CVE-2014-2064)

  - A cross-site scripting vulnerability due to improper
    input validation to the 'iconSize' cookie.
    (CVE-2014-2065)

  - A session fixation vulnerability allows remote attackers
    to hijack web sessions. (CVE-2014-2066)

  - An information disclosure vulnerability in the 'doIndex'
    function in 'hudson/util/RemotingDiagnostics.java'
    allows remote authenticated users with the
    'ADMINISTRATOR' permission to obtain sensitive
    information via heapDump. (CVE-2014-2068)"
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-02-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da47e3e2");
  # https://www.cloudbees.com/jenkins-security-advisory-2014-02-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?353dd087");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Jenkins 1.551 / 1.532.2 or Jenkins Enterprise 1.509.5.1 /
1.532.2.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
    ver_compare(ver:version, fix:'1.532.2', strict:FALSE) < 0 || # LTS version
    (
      ver[0] == 1 && ver[1] > 532 && ver[1] < 551 &&  # flag vulnerable major version releases,
      max_index(ver) < 3                              # but not future LTS releases
    )
  )
)
{
  vuln  = TRUE;
  fixed = "1.551 / 1.532.2";
}

# Check Enterprise ranges
if (
  enterprise_installed &&
  (
    # All previous
    (ver[0] < 1 || (ver[0] == 1 && ver[1] < 509))
    ||
    # 1.509.x < 1.509.5.1
    (ver[0] == 1 && ver[1] == 509 && (ver[2] < 5 || (ver[2] == 5 && ver[3] < 1)))
    ||
    # 1.532.x < 1.532.2.2
    (ver[0] == 1 && ver[1] == 532 && (ver[2] < 2 || (ver[2] == 2 && ver[3] < 2)))
  )
)
{
  vuln  = TRUE;
  fixed = "1.509.5.1 / 1.532.2.2";
}

if (vuln)
{
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
