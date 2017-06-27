#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70178);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id(
    "CVE-2013-3756",
    "CVE-2013-3767",
    "CVE-2013-3777",
    "CVE-2013-3778",
    "CVE-2013-3788",
    "CVE-2013-3747",
    "CVE-2013-3749"
  );
  script_bugtraq_id(61242, 61246, 61265, 61276, 61277, 61278, 61268);
  script_osvdb_id(95280, 95281, 95282, 95283, 95284, 95285, 95286);

  script_name(english:"Oracle E-Business (July 2013 CPU)");
  script_summary(english:"Checks for the July 2013 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the July 2013 Critical Patch Update (CPU). It is, therefore,
affected by security issues in the following components :

  - Oracle Landed Cost Management
  - Oracle Application Object Library
  - Oracle Applications Technology Stack
  - Oracle iSupplier Portal
  - Oracle Applications Technology Stack");

  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d601a70e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2013 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
  '11.5.10.2', '16772118,16772119',
  '12.0.6', '16772120',
  '12.1.1', '16772121',
  '12.1.2', '16772121',
  '12.1.3', '16772121'
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
