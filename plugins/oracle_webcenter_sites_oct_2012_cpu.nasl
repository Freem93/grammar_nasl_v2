#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72778);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2012-3183",
    "CVE-2012-3184",
    "CVE-2012-3185",
    "CVE-2012-3186",
    "CVE-2012-5065"
  );
  script_bugtraq_id(55968, 55972, 55980, 55984, 56001);
  script_osvdb_id(86297, 86298, 86299, 86300, 86301);
  script_xref(name:"EDB-ID", value:"22041");

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (October 2012 CPU)");
  script_summary(english:"Checks for Oracle 2012 CPU patches");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Oracle WebCenter Sites install is missing patches from the
October 2012 CPU.  As a result, it may be affected by multiple
vulnerabilities :

  - A cross-site request forgery vulnerability exists that
    can be triggered by tricking a victim into clicking an
    image link on a specially crafted page. (CVE-2012-3185)

  - A flaw in the UI Subcomponent could allow an
    authenticated user the ability to alter the email
    address information of other users. (CVE-2012-3183)

  - The UI Subcomponent is affected by a cross-site
    scripting vulnerability due to lack of sanitization for
    the 'username' and 'StartItem' parameters.
    (CVE-2012-3184)

  - The 'selectedLocale' parameter in the UI Subcomponent is
    not properly sanitized and allows SQL injection.
    (CVE-2012-3186)

  - The Oracle WebCenter Sites ImagePicket Subcomponent is
    affected by an unspecified local vulnerability.
    (CVE-2012-5065)"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate patch according to the October 2012 Oracle
Critical Patch Update advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

  #  Patch 14750912 - 11.1.1.6 < Revision 151599
  if (version =~ "^11\.1\.1\.6(\.|$)" && revision < 151599)
    fix = '\n  Fixed Revision : 151599' +
          '\n  Required Patch : 14750912';

  #  Patch 14583579 - 7.6.1 < Revision 148187
  if (version =~ "^7\.6\.1(\.|$)" && revision < 148187)
    fix = '\n  Fixed Revision : 148187' +
          '\n  Required Patch : 14583579';

  #  Patch 14583638 - 7.6.2 < Revision 148134
  if (version =~ "^7\.6\.2(\.|$)" && revision < 148134)
    fix = '\n  Fixed Revision : 148134' +
          '\n  Required Patch : 14583638';

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
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);

  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Oracle WebCenter Sites");
