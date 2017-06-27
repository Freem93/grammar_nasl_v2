#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78859);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id(
    "CVE-2013-2186",
    "CVE-2014-1869",
    "CVE-2014-3661",
    "CVE-2014-3662",
    "CVE-2014-3663",
    "CVE-2014-3664",
    "CVE-2014-3666",
    "CVE-2014-3667",
    "CVE-2014-3678",
    "CVE-2014-3679",
    "CVE-2014-3680",
    "CVE-2014-3681"
  );
  script_bugtraq_id(63174, 65484);
  script_osvdb_id(
    98703,
    103029,
    112495,
    112499,
    112500,
    112501,
    112502,
    112503,
    112504,
    112505,
    112506,
    112507
  );

  script_name(english:"Jenkins < 1.583 / 1.565.3 and Jenkins Enterprise 1.532.x / 1.554.x / 1.565.x < 1.532.10.1 / 1.554.10.1 / 1.565.3.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Jenkins version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling and management system
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins (open source) or
CloudBees Jenkins Enterprise that is affected by multiple
vulnerabilities :

  - An error exists related to file upload processing that
    allows a remote attacker to overwrite arbitrary files.
    (CVE-2013-2186)

  - An input validation error exists related to the included
    'ZeroClipboard' component that allows cross-site
    scripting attacks. (CVE-2014-1869)

  - An error exists related to 'CLI handshake' handling that
    allows denial of service attacks. (CVE-2014-3661)

  - An error exists related to handling login attempts using
    non-existent or incorrect account names that allows a
    remote attacker to enumerate application user names.
    (CVE-2014-3662)

  - An error exists related to handling users having
    'Job/CONFIGURE' permissions that allows such users to
    perform actions meant only for 'Job/CREATE' permissions.
    (CVE-2014-3663)

  - An error exists related to handling users having
    'Overall/READ' permissions that allows directory
    traversal attacks. (CVE-2014-3664)

  - An error exists related to the 'CLI channel' that allows
    arbitrary code execution by a remote attacker on the
    Jenkins master. (CVE-2014-3666)

  - An error exists related to handling users having
    'Overall/READ' permissions that allows plugin source
    code to be disclosed. (CVE-2014-3667)

  - An input validation error exists related to the
    'Monitoring' plugin that allows cross-site scripting
    attacks. (CVE-2014-3678)

  - An error exists related to the 'Monitoring' plugin that
    allows unauthorized access to sensitive information.
    (CVE-2014-3679)

  - An error exists related to handling users having
    'Job/READ' permissions that allows such users to
    obtain default passwords belonging to parameterized
    jobs. (CVE-2014-3680)

  - An unspecified input validation error allows cross-site
    scripting attacks. (CVE-2014-3681)");
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-10-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1236c16f");
  # https://www.cloudbees.com/jenkins-security-advisory-2014-10-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f0783e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.583 / 1.565.3 or Jenkins Enterprise 1.532.10.1 /
1.554.10.1 / 1.565.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  # CVE-2013-2186

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins-ci:monitoring_plugin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
if (max_index(ver) < 2) audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);

if (
  report_paranoia > 1 && isnull(enterprise_installed) &&
  (
    ver_compare(ver:version, fix:'1.565.3', strict:FALSE) < 0 || # LTS version
    (
      ver[0] == 1 && ver[1] > 565 && ver[1] < 583 &&  # flag vulnerable major version releases,
      max_index(ver) < 3                              # but not future LTS releases
    )
  )
)
{
  vuln  = TRUE;
  fixed = "1.583 / 1.565.3";
}

# Check Enterprise ranges
# 1.565.1.1 up to 1.565.2.x
# 1.554.1.1 up to 1.554.9.x
# 1.532.1.1 up to 1.532.9.x
if (
  enterprise_installed &&
  (
    # All previous
    (ver[0] < 1 || (ver[0] == 1 && ver[1] < 509))
    ||
    # 1.565.1.1 up to 1.565.2.x
    (ver[0] == 1 && ver[1] == 565 && ((ver[2] == 1 && ver[3] >= 1) || (ver[2] == 2)))
    ||
    # 1.554.1.1 up to 1.554.9.x
    (ver[0] == 1 && ver[1] == 554 && ((ver[2] < 1 && ver[3] >= 1) || (ver[2] >= 2 && ver[2] <= 9)))
    ||
    # 1.532.1.1 up to 1.532.9.x
    (ver[0] == 1 && ver[1] == 532 && ((ver[2] < 1 && ver[3] >= 1) || (ver[2] >= 2 && ver[2] <= 9)))
  )
)
{
  vuln  = TRUE;
  fixed = "1.532.10.1 / 1.554.10.1 / 1.565.3.1";
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
