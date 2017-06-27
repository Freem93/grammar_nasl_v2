#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86577);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/23 17:35:37 $");

  script_cve_id("CVE-2010-1622", "CVE-2015-4799");
  script_bugtraq_id(40954);
  script_osvdb_id(65661, 129080);

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks for Oracle 2015 CPU patches.");

  script_set_attribute(attribute:"synopsis", value:
"The website content management system installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version Oracle WebCenter Sites installed on the remote host is
missing security patches from the October 2015 Critical Patch Update
(CPU). It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the bundled SpringSource Spring
    Framework that allows a remote attacker to execute
    arbitrary code via an HTTP request containing
    class.classLoader.URLs[0]=jar: followed by an URL of a
    crafted .jar file. (CVE-2010-1622)

  - An unspecified flaw exists in the Security subcomponent
    that allows a remote attacker to impact integrity.
    (CVE-2015-4799)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");

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
if (isnull(versions)) exit(1, 'Unable to obtain a version list for Oracle WebCenter Sites.');

report = '';

foreach key (keys(versions))
{
  fix = '';

  version = versions[key];
  revision = get_kb_item(key - '/Version' + '/Revision');
  path = get_kb_item(key - '/Version' + '/Path');

  if (isnull(version) || isnull(revision)) continue;

  # Patch 21494888 - 11.1.1.8.0 < Revision 172153
  if (version =~ "^11\.1\.1\.8\.0$" && revision < 172153)
    fix = '\n  Fixed revision : 172153' +
          '\n  Required patch : 21494888';

  # Patch 21494867 - 11.1.1.6.1 < Revision 172158
  if (version =~ "^11\.1\.1\.6\.1$" && revision < 172158)
    fix = '\n  Fixed revision : 172158' +
          '\n  Required patch : 21494867';

  # Patch 21834997 - 7.6.2 < Revision 179663
  if (version =~ "^7\.6\.2(\.|$)" && revision < 179663)
    fix = '\n  Fixed revision : 179663' +
          '\n  Required patch : 21834997';

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
