#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90601);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/25 14:52:53 $");

  script_cve_id(
    "CVE-2016-0697",
    "CVE-2016-3434",
    "CVE-2016-3436",
    "CVE-2016-3437",
    "CVE-2016-3439",
    "CVE-2016-3447",
    "CVE-2016-3466"
  );
  script_osvdb_id(
    137254,
    137255,
    137256,
    137257,
    137258,
    137259,
    137260
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (April 2016 CPU)");
  script_summary(english:"Checks for the April 2016 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the April 2016 Oracle Critical Patch Update (CPU). It is,
therefore, affected by vulnerabilities in the following components :

  - An unspecified flaw exists in the DB Privileges
    subcomponent of the Oracle Applications Object Library
    component. A local attacker can exploit this to impact
    confidentiality and integrity. (CVE-2016-0697)

  - An unspecified flaw exists in the Logout subcomponent of
    the Oracle Applications Object Library component. A
    context-dependent attacker can exploit this to impact
    integrity. (CVE-2016-3434)

  - An unspecified flaw exists in the Tasks subcomponent of
    the Oracle Common Applications Calendar component. A
    context-dependent attacker can exploit this to impact
    confidentiality and integrity. (CVE-2016-3436)

  - An unspecified flaw exists in the Person Address Page
    subcomponent of the Oracle CRM Wireless component. A
    context-dependent attacker can exploit this to impact
    confidentiality and integrity. (CVE-2016-3437)

  - An unspecified flaw exists in the Call Phone Number Page
    subcomponent of the Oracle CRM Wireless component. A
    context-dependent attacker can exploit this to impact
    confidentiality and integrity. (CVE-2016-3439)

  - An unspecified flaw exists in the OAF Core subcomponent
    of the Oracle Applications Framework component. A
    context-dependent attacker can exploit this to impact
    confidentiality and integrity. (CVE-2016-3447)

  - An unspecified flaw exists in the Wireless subcomponent
    of the Oracle Field Service. An unauthenticated, remote
    attacker can exploit this to impact confidentiality and
    integrity. (CVE-2016-3466)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/20");

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

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list('22614470'),
  '12.1.2', make_list('22614470'),
  '12.1.3', make_list('22614470'),

  '12.2.3', make_list('22614473'),
  '12.2.4', make_list('22614473'),
  '12.2.5', make_list('22614473')
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
