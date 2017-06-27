#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88042);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id(
    "CVE-2015-3195",
    "CVE-2015-4926",
    "CVE-2016-0454",
    "CVE-2016-0456",
    "CVE-2016-0457",
    "CVE-2016-0459",
    "CVE-2016-0507",
    "CVE-2016-0509",
    "CVE-2016-0510",
    "CVE-2016-0511",
    "CVE-2016-0512",
    "CVE-2016-0513",
    "CVE-2016-0514",
    "CVE-2016-0515",
    "CVE-2016-0516",
    "CVE-2016-0517",
    "CVE-2016-0518",
    "CVE-2016-0519",
    "CVE-2016-0520",
    "CVE-2016-0521",
    "CVE-2016-0523",
    "CVE-2016-0524",
    "CVE-2016-0525",
    "CVE-2016-0526",
    "CVE-2016-0527",
    "CVE-2016-0528",
    "CVE-2016-0529",
    "CVE-2016-0530",
    "CVE-2016-0531",
    "CVE-2016-0532",
    "CVE-2016-0533",
    "CVE-2016-0534",
    "CVE-2016-0536",
    "CVE-2016-0537",
    "CVE-2016-0538",
    "CVE-2016-0539",
    "CVE-2016-0542",
    "CVE-2016-0543",
    "CVE-2016-0544",
    "CVE-2016-0545",
    "CVE-2016-0547",
    "CVE-2016-0548",
    "CVE-2016-0549",
    "CVE-2016-0550",
    "CVE-2016-0551",
    "CVE-2016-0552",
    "CVE-2016-0553",
    "CVE-2016-0554",
    "CVE-2016-0555",
    "CVE-2016-0556",
    "CVE-2016-0557",
    "CVE-2016-0558",
    "CVE-2016-0559",
    "CVE-2016-0560",
    "CVE-2016-0561",
    "CVE-2016-0562",
    "CVE-2016-0563",
    "CVE-2016-0564",
    "CVE-2016-0565",
    "CVE-2016-0566",
    "CVE-2016-0567",
    "CVE-2016-0568",
    "CVE-2016-0569",
    "CVE-2016-0570",
    "CVE-2016-0571",
    "CVE-2016-0575",
    "CVE-2016-0576",
    "CVE-2016-0578",
    "CVE-2016-0579",
    "CVE-2016-0580",
    "CVE-2016-0581",
    "CVE-2016-0582",
    "CVE-2016-0583",
    "CVE-2016-0584",
    "CVE-2016-0585",
    "CVE-2016-0586",
    "CVE-2016-0588",
    "CVE-2016-0589"
  );
  script_bugtraq_id(78626);
  script_osvdb_id(
    131039,
    133242,
    133243,
    133244,
    133245,
    133246,
    133247,
    133248,
    133249,
    133250,
    133251,
    133252,
    133253,
    133254,
    133255,
    133256,
    133257,
    133258,
    133259,
    133260,
    133261,
    133262,
    133263,
    133264,
    133265,
    133266,
    133267,
    133268,
    133269,
    133270,
    133271,
    133272,
    133273,
    133274,
    133275,
    133276,
    133277,
    133278,
    133279,
    133280,
    133281,
    133282,
    133283,
    133284,
    133285,
    133286,
    133287,
    133288,
    133289,
    133290,
    133291,
    133292,
    133293,
    133294,
    133295,
    133296,
    133297,
    133298,
    133299,
    133300,
    133301,
    133302,
    133303,
    133304,
    133305,
    133306,
    133307,
    133308,
    133309,
    133310,
    133311,
    133312,
    133313,
    133314,
    133315,
    133316,
    133317,
    133318,
    136380,
    136382
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (January 2016 CPU)");
  script_summary(english:"Checks for the January 2016 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business Suite installed on the remote host is
missing the January 2016 Critical Patch Update. It is, therefore,
affected by multiple unspecified vulnerabilities in multiple
components and subcomponents, the most severe of which can allow an
unauthenticated, remote attacker to affect both confidentiality and
integrity.");
  #http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1a16c5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
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
  '11.5.10.2', make_list('22133429', '22133397'),

  '12.1.1', make_list('22133441'),
  '12.1.2', make_list('22133441'),
  '12.1.3', make_list('22133441'),

  '12.2.2', make_list('22133451'),
  '12.2.3', make_list('22133451'),
  '12.2.4', make_list('22133451')
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
