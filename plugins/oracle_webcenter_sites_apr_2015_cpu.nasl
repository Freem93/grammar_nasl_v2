#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83469);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id("CVE-2014-0050", "CVE-2014-0112");
  script_bugtraq_id(65400, 67064);
  script_osvdb_id(102945, 103918);

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (April 2015 CPU)");
  script_summary(english:"Checks for Oracle 2015 CPU patches.");

  script_set_attribute(attribute:"synopsis", value:
"The website content management system installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle WebCenter Sites installed on the remote host is missing
patches from the April 2015 CPU. It is, therefore, affected by
multiple vulnerabilities :

  - A flaw exists within 'MultipartStream.java' in Apache
    Commons FileUpload when parsing malformed Content-Type
    headers. A remote attacker, using a crafted header,
    can exploit this to cause an infinite loop, resulting
    in a denial of service. (CVE-2014-0050)

  - ParametersInterceptor in Apache Struts does not properly
    restrict access to the getClass method. A remote
    attacker, using a crafted request, can exploit this to
    manipulate the ClassLoader, thus allowing the execution
    of arbitrary code. (CVE-2014-0112)");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies('oracle_webcenter_sites_installed.nbin');
  script_require_keys('SMB/WebCenter_Sites/Installed');
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

port = kb_smb_transport();

get_kb_item_or_exit('SMB/WebCenter_Sites/Installed');

versions = get_kb_list('SMB/WebCenter_Sites/*/Version');
if (isnull(versions)) exit(1, 'Unable to obtain version list for Oracle WebCenter Sites');

report = '';

foreach key (keys(versions))
{
  fix = '';

  version = versions[key];
  revision = get_kb_item(key - '/Version' + '/Revision');
  path = get_kb_item(key - '/Version' + '/Path');

  if (isnull(version) || isnull(revision)) continue;

  # Patch 19278850 - 11.1.1.8.0 < Revision 165274
  if (version =~ "^11\.1\.1\.8\.0$" && revision < 165274)
    fix = '\n  Fixed Revision : 165274' +
          '\n  Required Patch : 19278850';

  # Patch 18846487 - 11.1.1.6.1 < Revision 164040
  if (version =~ "^11\.1\.1\.6\.1$" && revision < 164040)
    fix = '\n  Fixed Revision : 164040' +
          '\n  Required Patch : 18846487';

  # Patch 20617648 - 7.6.2 < Revision 162566
  if (version =~ "^7\.6\.2(\.|$)" && revision < 162566)
    fix = '\n  Fixed Revision : 162566' +
          '\n  Required Patch : 20617648';

  if (fix != '')
  {
    if (!isnull(path)) report += '\n  Path           : ' + path;
    report += '\n  Version        : ' + version +
              '\n  Revision       : ' + revision +
              fix + '\n';
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Oracle WebCenter Sites");
