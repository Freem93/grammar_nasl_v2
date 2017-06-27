#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86479);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id(
    "CVE-2015-4762",
    "CVE-2015-4798",
    "CVE-2015-4839",
    "CVE-2015-4845",
    "CVE-2015-4846",
    "CVE-2015-4849",
    "CVE-2015-4851",
    "CVE-2015-4854",
    "CVE-2015-4865",
    "CVE-2015-4884",
    "CVE-2015-4886",
    "CVE-2015-4898"
  );
  script_bugtraq_id(
    77243,
    77244,
    77245,
    77247,
    77248,
    77249,
    77250,
    77251,
    77252,
    77253,
    77254,
    77255
  );
  script_osvdb_id(
    129093,
    129094,
    129095,
    129096,
    129097,
    129098,
    129099,
    129100,
    129101,
    129102,
    129103,
    129104
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks for the October 2015 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the October 2015 Oracle Critical Patch Update (CPU). It is,
therefore, affected by vulnerabilities in the following components :

  - An unspecified flaw exists in the Online Patching
    subcomponent in the Applications DBA. An authenticated,
    remote attacker can exploit this to gain access to
    sensitive information. (CVE-2015-4762)

  - Unspecified flaws exist in the DB Listener subcomponent
    in the Applications Technology Stack. An authenticated,
    remote attacker can exploit these to cause a denial of
    service. (CVE-2015-4798, CVE-2015-4839)

  - An unspecified flaw exists in the Application Object
    Library related to the 'Java APIs - AOL/J' subcomponent.
    An unauthenticated, remote attacker can exploit this to
    gain access to sensitive information. (CVE-2015-4845)

  - An unspecified flaw exists in the SQL Extensions
    subcomponent in the Applications Manager. An
    authenticated, remote attacker can exploit this to
    impact integrity and confidentiality. (CVE-2015-4846)

  - An unspecified flaw exists in the Punch-in subcomponent
    in the Oracle Payments component. An unauthenticated,
    remote attacker can exploit this to impact integrity.
    (CVE-2015-4849)

  - An unspecified flaw exists in the XML Input subcomponent
    in the iSupplier Portal. An unauthenticated, remote
    attacker can exploit this to impact integrity.
    (CVE-2015-4851)

  - An unspecified flaw exists in the Application Object
    Library related to the Single Signon subcomponent.
    An unauthenticated, remote attacker can exploit this to
    impact integrity. (CVE-2015-4854)

  - An unspecified flaw exists in the Applications Framework
    related to the 'Business Objects - BC4J' subcomponent.
    An authenticated, remote attacker can exploit this to
    gain access to sensitive information. (CVE-2015-4865)

  - An unspecified flaw exists in the Single Signon
    subcomponent in the Application Object Library. An
    unauthenticated, remote attacker can exploit this to
    gain access to sensitive information. (CVE-2015-4884)

  - An unspecified flaw exists in the Reports Security
    subcomponent in the Report Manager. An unauthenticated,
    remote attacker can exploit this to impact integrity
    and confidentiality.(CVE-2015-4886)

  - An unspecified flaw exists in the Applications Framework
    related to the 'Diagnostics, DMZ' subcomponent. An
    authenticated, remote attacker can exploit this to
    impact integrity. (CVE-2015-4898)");
  # www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d408555");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
  '11.5.10.2', make_list('21507439', '21507445'),

  '12.0.6', make_list('21507421'),

  '12.1.3', make_list('21507207'),

  '12.2.3', make_list('21507429'),
  '12.2.4', make_list('21507429')
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
