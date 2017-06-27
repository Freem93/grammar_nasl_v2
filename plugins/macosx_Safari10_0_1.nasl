#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95411);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/13 17:57:45 $");

  script_cve_id(
    "CVE-2016-4613",
    "CVE-2016-4666",
    "CVE-2016-4677",
    "CVE-2016-7578"
  );
  script_bugtraq_id(
    93851,
    93853,
    93949
  );
  script_osvdb_id(
    146214,
    146215,
    146224,
    146369
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-10-24-3");

  script_name(english:"macOS : Apple Safari < 10.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Mac OS X or macOS host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X or macOS
host is prior to 10.0.1. It is, therefore, affected by multiple
vulnerabilities in WebKit :

  - An unspecified flaw exists in state management due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted web content, to disclose sensitive
    user information. (CVE-2016-4613)

  - Multiple memory corruption issues exist due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit these, via specially crafted
    web content, to execute arbitrary code. (CVE-2016-4666,
    CVE-2016-4677, CVE-2016-7578)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/kb/HT207272");
  # http://lists.apple.com/archives/security-announce/2016/Oct/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe4ceff9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 10.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
vcf::apple::check_macos_restrictions(restrictions:['10.10', '10.11', '10.12']);

app_info = vcf::apple::get_safari_info();
constraints = [{"fixed_version" : "10.0.1"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
