#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92461);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id(
    "CVE-2016-3491",
    "CVE-2016-3512",
    "CVE-2016-3520",
    "CVE-2016-3522",
    "CVE-2016-3523",
    "CVE-2016-3524",
    "CVE-2016-3525",
    "CVE-2016-3528",
    "CVE-2016-3532",
    "CVE-2016-3533",
    "CVE-2016-3534",
    "CVE-2016-3535",
    "CVE-2016-3536",
    "CVE-2016-3541",
    "CVE-2016-3542",
    "CVE-2016-3543",
    "CVE-2016-3545",
    "CVE-2016-3546",
    "CVE-2016-3547",
    "CVE-2016-3548",
    "CVE-2016-3549",
    "CVE-2016-3558",
    "CVE-2016-3559"
  );
  script_bugtraq_id(
    91838,
    91839,
    91841,
    91843,
    91845,
    91848,
    91852,
    91857,
    91861,
    91865,
    91870,
    91873,
    91878,
    91882,
    91886,
    91888,
    91893,
    91896,
    91899,
    91903,
    91907,
    91909,
    91911
  );
  script_osvdb_id(
    141838,
    141839,
    141840,
    141841,
    141842,
    141843,
    141844,
    141845,
    141846,
    141847,
    141848,
    141849,
    141850,
    141851,
    141852,
    141853,
    141854,
    141855,
    141856,
    141857,
    141858,
    141859,
    141860
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (July 2016 CPU)");
  script_summary(english:"Checks for the July 2016 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the July 2016 Oracle Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Wireless Framework
    subcomponent within the CRM Technical Foundation
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-3491)

  - An unspecified flaw exists in the Function Security
    subcomponent within the Customer Interaction History
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-3512)

  - An unspecified flaw exists in the AOL diagnostic tests
    subcomponent within the Application Object Library
    component that allows an authenticated, remote attacker
    to disclose potentially sensitive information.
    (CVE-2016-3520)

  - An unspecified flaw exists in the Application Service
    subcomponent within the Web Applications Desktop
    Integrator component that allows an unauthenticated,
    remote attacker to impact confidentiality and integrity.
    (CVE-2016-3522)

  - An unspecified flaw exists in the Application Service
    subcomponent within the Web Applications Desktop
    Integrator component that allows an unauthenticated,
    remote attacker to impact integrity. (CVE-2016-3523)

  - An unspecified flaw exists in the Configuration
    subcomponent within the Applications Technology Stack
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-3524)

  - An unspecified flaw exists in the Cookie Management
    subcomponent within the Applications Manager component
    that allows an unauthenticated, remote attacker to
    disclose potentially sensitive information.
    (CVE-2016-3525)

  - An unspecified flaw exists in the Expenses Admin
    Utilities subcomponent within the Internet Expenses
    component that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3528)

  - An unspecified flaw exists in the SDK client integration
    subcomponent within the Advanced Inbound Telephony
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-3532)

  - An unspecified flaw exists in the Search subcomponent
    within the Knowledge Management component that allows an
    unauthenticated, remote attacker to impact integrity.
    (CVE-2016-3533)

  - An unspecified flaw exists in the Engineering Change
    Order subcomponent within the Installed Base component
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-3534)

  - An unspecified flaw exists in the Remote Launch
    subcomponent within the CRM Technical Foundation
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-3535)

  - An unspecified flaw exists in the Deliverables
    subcomponent within the Marketing component that allows
    an unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-3536)

  - An unspecified flaw exists in the Notes subcomponent
    within the Common Applications Calendar component that
    allows an unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-3541)

  - An unspecified flaw exists in the Search/Browse
    subcomponent within the Knowledge Management component
    that allows an authenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2016-3542)

  - An unspecified flaw exists in the Tasks subcomponent
    within the Common Applications Calendar component that
    allows an unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2016-3543)

  - An unspecified flaw exists in the Web based help screens
    subcomponent within the Application Object Library
    component that allows an unauthenticated, remote
    attacker to disclose potentially sensitive information.
    (CVE-2016-3545)

  - An unspecified flaw exists in the Report JSPs
    subcomponent within the Advanced Collections component
    that allows an unauthenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2016-3546)

  - An unspecified flaw exists in the Content Manager
    subcomponent within the One-to-One Fulfillment component
    that allows an unauthenticated, remote attacker to
    disclose potentially sensitive information.
    (CVE-2016-3547)

  - An unspecified flaw exists in the Marketing activity
    collateral subcomponent within the Marketing component
    that allows an unauthenticated, remote attacker to
    disclose potentially sensitive information.
    (CVE-2016-3548)

  - An unspecified flaw exists in the Search Integration
    Engine subcomponent within the E-Business Suite Secure
    Enterprise Search component that allows an
    unauthenticated, remote attacker to disclose potentially
    sensitive information. (CVE-2016-3549)

  - Multiple unspecified flaws exist in the Email Center
    Agent Console subcomponent within the Email Center
    component that allow an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-3558,
    CVE-2016-3559)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:e-business_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

p12_1 = '23144507';
p12_2 = '23144508';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list(p12_1),
  '12.1.2', make_list(p12_1),
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2)
);

patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = affected_versions[version];
  foreach required_patch (patchids)
  {
    foreach applied_patch (patches)
    {
      if(required_patch == applied_patch)
      {
        patched = applied_patch;
        break;
      }
    }
    if(patched) break;
  }
  if(!patched) patchreport = join(patchids,sep:" or ");
}

if (!patched && affectedver)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+version+' Patch '+patchreport+
      '\n';
    security_hole(port:0,extra:report);
  }
  else security_hole(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
