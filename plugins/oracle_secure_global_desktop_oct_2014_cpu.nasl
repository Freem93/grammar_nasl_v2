#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78543);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/25 05:40:36 $");

  script_cve_id(
    "CVE-2014-2472",
    "CVE-2014-2473",
    "CVE-2014-2474",
    "CVE-2014-2475",
    "CVE-2014-2476",
    "CVE-2014-6459"
  );
  script_bugtraq_id(70459, 70464, 70476, 70479, 70481, 70491);
  script_osvdb_id(113351, 113355, 113356, 113357, 113359, 113360);

  script_name(english:"Oracle Secure Global Desktop Multiple DoS Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Oracle Secure Global Desktop that is
affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle Secure Global Desktop that is
version 4.63, 4.71, 5.0 or 5.1. It is, therefore, affected by multiple
denial of service vulnerabilities in the following components :

  - SGD Proxy Server (ttaauxserv)
  - SGD SSL Daemon (ttassl)

Note that only CVE-2014-2475 affects versions 4.63 and 4.71.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

if (version =~ "^5\.10($|\.)") fix_required = 'Patch_51p4';
if (version =~ "^5\.00($|\.)") fix_required = 'Patch_50p4';
if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p4';
if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p4';

if (fix_required == '') audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version);

patches = get_kb_list("Host/Oracle_Secure_Global_Desktop/Patches");

patched = FALSE;
foreach patch (patches)
  if (patch == fix_required) patched = TRUE;

if (patched) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version + ' (with ' + fix_required + ')');

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Patch required    : ' + fix_required +
           '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
