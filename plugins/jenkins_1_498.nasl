#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65055);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id("CVE-2013-0158");
  script_bugtraq_id(57171);
  script_osvdb_id(89055);

  script_name(english:"Jenkins < 1.498 / 1.480.2 and Jenkins Enterprise 1.447.x / 1.466.x < 1.447.6.1 / 1.466.12.1 Unspecified Master Cryptographic Key Information Disclosure");
  script_summary(english:"Checks Jenkins version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a job scheduling / management system that
is affected by an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts a version of Jenkins or Jenkins Enterprise
that is affected by an information disclosure vulnerability that could
allow a remote attacker to gain access to master cryptographic key
information.  Attackers with this information may be able to execute
arbitrary code on the master host."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2013-01-04
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f8bc6d8");
  # http://www.cloudbees.com/jenkins-advisory/jenkins-security-advisory-2013-01-04.cb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddc1507c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.498 / 1.480.2, Jenkins Enterprise 1.447.6.1 /
1.466.12.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/07");
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

# Check Open Source ranges
if (
  report_paranoia > 1 && isnull(enterprise_installed) &&
  (
    ver_compare(ver:version, fix:'1.480.2', strict:FALSE) == -1 || # LTS version
    (
      ver[0] == 1 && ver[1] > 480 && ver[1] < 498 &&  # flag vulnerable major version releases,
      max_index(ver) < 3                              # but not future LTS releases
    )
  )
)
{
  vuln  = TRUE;
  fixed = "1.498 / 1.480.2";
}

# Check Enterprise ranges
if (
  enterprise_installed &&
  (
    # All previous
    (ver[0] < 1 || (ver[0] == 1 && ver[1] < 447))
    ||
    # 1.447.x < 1.447.6.1
    (ver[0] == 1 && ver[1] == 447 && (ver[2] < 6 || (ver[2] == 6 && ver[3] < 1)))
    ||
    # 1.466.x < 1.466.12.1
    (ver[0] == 1 && ver[1] == 466 && (ver[2] < 12 || (ver[2] == 12 && ver[3] < 1)))
  )
)
{
  vuln  = TRUE;
  fixed = "1.447.6.1 / 1.466.12.1";
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Product           : ' + appname +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';

    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
