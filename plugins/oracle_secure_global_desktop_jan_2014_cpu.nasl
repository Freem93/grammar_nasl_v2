#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72339);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/09 15:44:48 $");

  script_cve_id(
    "CVE-2012-3544",
    "CVE-2013-2067",
    "CVE-2013-2071",
    "CVE-2014-0419"
  );
  script_bugtraq_id(59797, 59798, 59799, 64902);
  script_osvdb_id(93252, 93253, 93254, 102110);

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (January 2014 CPU)");
  script_summary(english:"Checks version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Oracle Secure Global Desktop that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle Secure Global Desktop
installed that is affected by multiple vulnerabilities :

  - Specially crafted requests sent with chunked transfer
    encoding could allow a remote attacker to perform a
    'limited' denial of service attack on the Tomcat server.
    (CVE-2012-3544)

  - The Tomcat server is affected by a session fixation
    vulnerability in the FORM authenticator. (CVE-2013-2067)

  - The Apache Tomcat AsyncListener method is affected by a
    cross-session information disclosure vulnerability when
    handling user requests. (CVE-2013-2071)

  - The Administration Console and Workspace Web
    Applications subcomponent is affected by an unspecified,
    remote vulnerability. (CVE-2014-0419)");
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c46362");
  # https://blogs.oracle.com/virtualization/entry/important_patch_set_updates_psu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?254d3b2e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the the January 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (version =~ "^5\.00($|\.)") fix_required = 'Patch_50p1';
if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p1';
if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p1';

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
  security_warning(port:0, extra:report);
}
else security_warning(0);
