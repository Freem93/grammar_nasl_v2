#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100027);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id(
    "CVE-2009-3270",
    "CVE-2009-3560",
    "CVE-2009-3720",
    "CVE-2012-1147",
    "CVE-2012-1148",
    "CVE-2012-6702",
    "CVE-2013-7443",
    "CVE-2015-1283",
    "CVE-2015-3414",
    "CVE-2015-3415",
    "CVE-2015-3416",
    "CVE-2015-3717",
    "CVE-2015-6607",
    "CVE-2016-0718",
    "CVE-2016-4472",
    "CVE-2016-5300",
    "CVE-2016-6153"
  );
  script_bugtraq_id(
    36097,
    37203,
    52379,
    74228,
    75491,
    75973,
    76089,
    76970,
    79354,
    90729,
    91159,
    91483,
    91528,
    91546
  );
  script_osvdb_id(
    58399,
    59737,
    60797,
    80892,
    80893,
    80894,
    120909,
    120943,
    120944,
    122039,
    123915,
    124928,
    138680,
    139342,
    140838,
    151459,
    154558,
    154559
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-03-22-2");
  script_xref(name:"EDB-ID", value:"12509");

  script_name(english:"Apple iTunes < 12.6 Multiple Vulnerabilities (macOS) (credentialed check)");
  script_summary(english:"Checks iTunes version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote macOS or Mac OS X
host is prior to 12.6. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple vulnerabilities exist in the expat component,
    the most severe of which are remote code execution
    vulnerabilities. An unauthenticated, remote attacker can
    exploit these vulnerabilities to cause a denial of
    service condition or the execution of arbitrary code in
    the context of the current user. (CVE-2009-3270,
    CVE-2009-3560, CVE-2009-3720, CVE-2012-1147,
    CVE-2012-1148, CVE-2012-6702, CVE-2015-1283,
    CVE-2016-0718, CVE-2016-4472, CVE-2016-5300)

  - Multiple vulnerabilities exist in the SQLite component,
    the most severe of which are remote code execution
    vulnerabilities. An unauthenticated, remote attacker can
    exploit these vulnerabilities by convincing a user to
    open a specially crafted file, to cause a denial of
    service condition or the execution of arbitrary code in
    the context of the current user. (CVE-2013-7443,
    CVE-2015-3414, CVE-2015-3415, CVE-2015-3416,
    CVE-2015-3717, CVE-2015-6607, CVE-2016-6153)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207598");
  # https://lists.apple.com/archives/security-announce/2017/Mar/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b01bc68");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes version 12.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "12.6"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
