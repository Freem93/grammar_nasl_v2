#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82829);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/19 04:39:47 $");

  script_cve_id("CVE-2015-0447","CVE-2015-0504","CVE-2015-2565");
  script_bugtraq_id(74080,74087,74096);
  script_osvdb_id(120675,120676,120677);

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (April 2015 CPU)");
  script_summary(english:"Checks for the April 2015 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the April 2015 Oracle Critical Patch Update (CPU). It is,
therefore, affected by vulnerabilities in the following components :

  - A unspecified flaw exists related to the Configurator
    DMZ rules subcomponent in the Applications Technology
    Stack component that allows a remote attacker to gain
    access to sensitive information. (CVE-2015-0447)

  - A unspecified flaw exists related to the Error Messages
    subcomponent in the Application Object Library component
    that allows a remote attacker to impact integrity.
    (CVE-2015-0504)

  - A unspecified flaw exists related to the Create Item
    Instance subcomponent in the Installed Base component
    that allows a remote attacker to impact integrity.
    (CVE-2015-2565)");

  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

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
  '11.5.10.2' , make_list('20406605','20406604'),

  '12.0.6'    , make_list('20406627'),

  '12.1.1'    , make_list('20406628'),
  '12.1.2'    , make_list('20406628'),
  '12.1.3'    , make_list('20406628'),

  '12.2.3'    , make_list('20406630'),
  '12.2.4'    , make_list('20406630')
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
