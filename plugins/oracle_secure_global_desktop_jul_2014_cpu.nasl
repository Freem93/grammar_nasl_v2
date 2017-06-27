#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76570);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id(
    "CVE-2013-4286",
    "CVE-2014-0033",
    "CVE-2014-0098",
    "CVE-2014-0211",
    "CVE-2014-0224",
    "CVE-2014-4232"
  );
  script_bugtraq_id(65769, 65773, 66303, 67382, 67899, 68606);
  script_osvdb_id(103705, 103708, 104580, 106980, 107729);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (July 2014 CPU)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Oracle Secure Global Desktop that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle Secure Global Desktop that is
version 4.63, 4.71, 5.0 or 5.1. It is, therefore, affected by the
following vulnerabilities :

  - Apache Tomcat does not properly handle certain
    inconsistent HTTP request headers, which allows remote
    attackers to trigger incorrect identification of a
    request's length and conduct request-smuggling attacks.
    (CVE-2013-4286)

  - CoyoteAdapter.java in Apache Tomcat does not consider
    the 'disableURLRewriting' setting when handling session
    ID in a URL, allowing a remote attacker to conduct
    session fixation attacks via a crafted URL.
    (CVE-2014-0033)

  - The 'log_cookie' function in mod_log_config.c of Apache
    will not handle specially crafted cookies during
    truncation, allowing a remote attacker to cause a denial
    of service via a segmentation fault. (CVE-2014-0098)

  - Multiple integer overflows within X.Org libXfont that
    could allow remote font servers to execute arbitrary
    code via a crafted xfs reply, which triggers a buffer
    overflow. (CVE-2014-0211)

  - OpenSSL does not properly restrict processing of
    'ChangeCipherSpec' messages which allows
    man-in-the-middle attackers to trigger use of a
    zero-length master key and consequently hijack sessions
    or obtain sensitive information via a crafted TLS
    handshake. (CVE-2014-0224)

  - An unspecified flaw related to the Workspace Web
    Application subcomponent could allow a remote attacker
    to impact integrity. (CVE-2014-4232)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

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

if (version =~ "^5\.10($|\.)") fix_required = 'Patch_51p3';
if (version =~ "^5\.00($|\.)") fix_required = 'Patch_50p3';
if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p3';
if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p3';

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
  security_hole(port:0, extra:report);
}
else security_hole(0);
