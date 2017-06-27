#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80952);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/18 18:41:38 $");

  script_cve_id(
    "CVE-2014-6525",
    "CVE-2014-6556",
    "CVE-2014-6572",
    "CVE-2014-6581",
    "CVE-2014-6582",
    "CVE-2014-6583",
    "CVE-2015-0380",
    "CVE-2015-0393",
    "CVE-2015-0404",
    "CVE-2015-0415"
  );
  script_bugtraq_id(
    72222,
    72224,
    72228,
    72230,
    72231,
    72232,
    72233,
    72236,
    72239,
    72241
  );
  script_osvdb_id(
    117267,
    117268,
    117269,
    117270,
    117271,
    117272,
    117273,
    117274,
    117275,
    117276
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (January 2015 CPU)");
  script_summary(english:"Checks for the January 2015 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the January 2015 Oracle Critical Patch Update (CPU). It is,
therefore, affected by vulnerabilities in the following components :

  - Oracle Application Object Library
  - Oracle Applications DBA
  - Oracle Applications DBA
  - Oracle Applications Framework
  - Oracle Customer Intelligence
  - Oracle Customer Interaction History
  - Oracle HCM Configuration Workbench
  - Oracle Marketing
  - Oracle Telecommunications Billing Integrator
  - Oracle Web Applications Desktop Integrator");

  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

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

# 12.0.1-5 go directly to 12.0.6 and apply patch, do not pass go, do not collect 200$
if(
  ver_compare(ver:version,fix:"12.0.1",strict:FALSE) >= 0 &&
  ver_compare(ver:version,fix:"12.0.5",strict:FALSE) <= 0
)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : 12.0.6 Patch 19873048'+
      '\n';
    security_hole(port:0,extra:report);
  }
  else security_hole(0);
  exit(0);
}

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

# Check if the installed version is an affected version
affected_versions = make_array(
  '11.5.10.2' , make_list('19873046','19873045'),

  '12.0.6'    , make_list('19873048'),

  '12.1.1'    , make_list('19873049'),
  '12.1.2'    , make_list('19873049'),
  '12.1.3'    , make_list('19873049'),

  '12.2.3'    , make_list('19873050'),
  '12.2.4'    , make_list('19873050')
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
