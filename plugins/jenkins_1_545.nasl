#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72743);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2013-6372");
  script_bugtraq_id(63864);
  script_osvdb_id(100107);

  script_name(english:"Jenkins < 1.545 Subversion Plugin Information Disclosure");
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
"The remote web server hosts a version of Jenkins that is affected by an
information disclosure vulnerability that could allow a local attacker
to obtain passwords and SSH private key passphrases related to accessing
Subversion resources."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2013-11-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1673c1b3");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Jenkins 1.545 or use the plugin update mechanism to obtain
Subversion plugin version 1.54 or greater."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

# Plugins can be updated independently,
# so scan must paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "Jenkins Open Source";

# Check if install is Enterprise; we do not want to check this
enterprise_installed = get_kb_item("www/Jenkins/"+port+"/enterprise/Installed");
if (!isnull(enterprise_installed)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

url = build_url(qs:'/', port:port);

version = get_kb_item_or_exit("www/Jenkins/"+port+"/JenkinsVersion");
if (version == "unknown") audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
if (max_index(ver) < 2) audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);

is_LTS = get_kb_item("www/Jenkins/"+port+"/is_LTS");
if (is_LTS)
  appname = "Jenkins Open Source LTS";

# All LTS for now are vuln <= 1.5.3.2
if (is_LTS && ver_compare(ver:version, fix:'1.532.2', strict:FALSE) <= 0)
  fix = "Upgrade the Subversion plugin";

# All non-LTS < 1.545 are vuln in default install
if (!is_LTS && ver_compare(ver:version, fix:'1.545', strict:FALSE) < 0)
  fix = "1.545";

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Product           : ' + appname +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
