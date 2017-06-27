#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73596);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2013-6462", "CVE-2014-2439", "CVE-2014-2463");
  script_bugtraq_id(64694, 66854, 66860);
  script_osvdb_id(101842, 105903, 105904);

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (April 2014 CPU)");
  script_summary(english:"Checks version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Oracle Secure Global Desktop that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle Secure Global Desktop that is
version 4.63, 4.71, 5.0 or 5.1. It is, therefore, affected by the
following vulnerabilities :

  - A buffer overflow flaw exists in the 'bdfReadCharacters'
    function within 'bitmap/bdfread.c' of the included X.Org
    libXfont. This could allow a remote attacker to cause a
    denial of service attack or possibly execute arbitrary
    code. (CVE-2013-6462)

  - A flaw exists with the Workspace Web Application. This
    could allow a remote attacker to impact the integrity of
    the application. Note this only affects versions
    5.0 and 5.1 of Oracle Secure Global Desktop.
    (CVE-2014-2439)

  - A flaw exists with the Workspace Web Application. This
    could allow a remote attacker to impact the
    confidentiality and integrity of the application.
    (CVE-2014-2463)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported patch information.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23999f63");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

fix_required = '';

if (version =~ "^5\.01($|\.)") fix_required = 'Patch_51p2';
if (version =~ "^5\.00($|\.)") fix_required = 'Patch_50p2';
if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p2';
if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p2';

if (fix_required == '') audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version);

patches = get_kb_list("Host/Oracle_Secure_Global_Desktop/Patches");

patched = FALSE;
foreach patch (patches)
  if (patch == fix_required) patched = TRUE;

if (patched) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version + ' (with ' + fix_required + ')');

if (report_verbosity > 0)
{
  report = '\n  Version          : ' + version +
           '\n  Patch Required   : ' + fix_required +
           '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
