#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84766);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id(
    "CVE-2014-3571",
    "CVE-2015-1926",
    "CVE-2015-2610",
    "CVE-2015-2615",
    "CVE-2015-2618",
    "CVE-2015-2630",
    "CVE-2015-2645",
    "CVE-2015-2652",
    "CVE-2015-4728",
    "CVE-2015-4739",
    "CVE-2015-4741",
    "CVE-2015-4743",
    "CVE-2015-4765"
  );
  script_bugtraq_id(
    71937,
    75772,
    75782,
    75783,
    75786,
    75787,
    75788,
    75789,
    75790,
    75791,
    75792,
    75795,
    75860
  );
  script_osvdb_id(
    116793,
    124243,
    124667,
    124668,
    124669,
    124670,
    124671,
    124672,
    124673,
    124674,
    124675,
    124676,
    124677
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (July 2015 CPU)");
  script_summary(english:"Checks for the July 2015 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the July 2015 Oracle Critical Patch Update (CPU). It is,
therefore, affected by affected by vulnerabilities in the following
components :

  - Oracle Application Object Library (CVE-2015-2618)
  - Oracle Application Object Library (CVE-2015-4739)
  - Oracle Applications DBA (CVE-2015-4743)
  - Oracle Applications Framework (CVE-2015-1926)
  - Oracle Applications Framework (CVE-2015-2610)
  - Oracle Applications Framework (CVE-2015-2615)
  - Oracle Applications Framework (CVE-2015-4741)
  - Oracle Applications Manager (CVE-2015-4765)
  - Oracle HTTP Server (CVE-2014-3571)
  - Oracle Marketing (CVE-2015-2652)
  - Oracle Sourcing (CVE-2015-4728)
  - Oracle Web Applications Desktop Integrator
    (CVE-2015-2645)
  - Technology stack (CVE-2015-2630)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
  '11.5.10.2' , make_list('20953336','20953337'),

  '12.0.6'    , make_list('20953339'),

  '12.1.1'    , make_list('20953340'),
  '12.1.2'    , make_list('20953340'),
  '12.1.3'    , make_list('20953340'),

  '12.2.3'    , make_list('20953338'),
  '12.2.4'    , make_list('20953338')
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
    security_warning(port:0,extra:report);
  }
  else security_warning(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
