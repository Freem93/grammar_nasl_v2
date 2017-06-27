#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76596);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:44:48 $");

  script_cve_id(
    "CVE-2014-0224",
    "CVE-2014-2482",
    "CVE-2014-4213",
    "CVE-2014-4235",
    "CVE-2014-4248"
  );
  script_bugtraq_id(67899, 68647, 68648, 68651, 68653);
  script_osvdb_id(107729, 109106, 109107, 109108, 109109);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Oracle E-Business (July 2014 CPU)");
  script_summary(english:"Checks for the Oracle July 2014 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the July 2014 Critical Patch Update (CPU). It is, therefore,
affected by vulnerabilities in the following components :

  - Oracle Applications Technology Stack
  - Oracle Concurrent Processing
  - Oracle Applications Manager
  - Oracle iStore
  - Oracle Applications Object Library");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

# Check if the installed version is an affected version
affected_versions = make_array(
  '11.5.10.2', '18122009,18122010',
  '12.0.6', '18122011',
  '12.1.1', '18122013',
  '12.1.2', '18122013',
  '12.1.3', '18122013',
  '12.2.2', '18122014',
  '12.2.3', '18122014'
);

patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = split(affected_versions[version], sep:',', keep:FALSE);
  for (i=0; i < max_index(patchids); i++)
  {
    for (j=0; j < max_index(patches); j++)
    {
      if (patchids[i] == patches[j])
      {
        patched = patchids[i];
        break;
      }
      if (patched) break;
    }
  }
}

if (!patched && affectedver)
{
  security_warning(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
