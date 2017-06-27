#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91102);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/11 13:15:59 $");

  script_cve_id(
    "CVE-2016-1113",
    "CVE-2016-1114",
    "CVE-2016-1115"
  );
  script_bugtraq_id(90506, 90507, 90514);
  script_osvdb_id(
    129952,
    130424,
    138222,
    138223,
    138224
  );
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Adobe ColdFusion Multiple Vulnerabilities (APSB16-16) (credentialed check)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis",value:
"A web-based application running on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe ColdFusion running on the remote Windows host is
missing a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input. An attacker
    can exploit this to execute arbitrary script code in a
    user's browser session. (CVE-2016-1113)

  - A remote code execution vulnerability exists in the
    Apache Commons Collections (ACC) library that is
    triggered during the deserialization of Java Objects. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code on the target host.
    (CVE-2016-1114)

  - A flaw exists related to certificate validation due to
    the server hostname not being verified to match a domain
    name in the Subject's Common Name (CN) or SubjectAltName
    field when handling wild card certificates. A
    man-in-the-middle attacker can exploit this by spoofing
    the TLS/SSL server via a certificate that appears valid,
    resulting the disclosure or manipulation of transmitted
    data. (CVE-2016-1115)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb16-16.html");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution",value:
"Apply the relevant hotfix as referenced in Adobe Security Bulletin
APSB16-16.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");

versions = make_list('10.0.0', '11.0.0', '2016.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "10.0.0")
  {
    # CF10 uses an installer for updates so it is less likely (perhaps not possible) to only partially install a hotfix.
    # this means the plugin doesn't need to check for anything in the CFIDE directory, it just needs to check the CHF level
    info = check_jar_chf(name, 19);
  }
  else if (ver == "11.0.0")
  {
    info = check_jar_chf(name, 8);
  }

 else if (ver == "2016.0.0")
  {
    info = check_jar_chf(name, 1);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

port = get_kb_item("SMB/transport");
if (!port)
  port = 445;

report =
  '\n' + 'Nessus detected the following unpatched instances :' +
  '\n' + join(instance_info, sep:'\n') +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
exit(0);
