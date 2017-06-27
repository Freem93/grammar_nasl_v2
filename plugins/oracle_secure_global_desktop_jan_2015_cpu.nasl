#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80912);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-5704"
  );
  script_bugtraq_id(
    68678,
    68742,
    68745,
    70574,
    70586
  );
  script_osvdb_id(
    109216,
    109231,
    109234,
    113251,
    113374
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (January 2015 CPU) (POODLE)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Oracle Secure Global Desktop that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle Secure Global Desktop that is
version 4.63, 4.71, 5.0 or 5.1. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Apache HTTP Server
  - Client
  - Gateway JARP module
  - Gateway Reverse Proxy
  - OpenSSL
  - Print Servlet (only in 5.0 / 5.1)
  - SGD SSL Daemon (ttassl)
  - Web Server");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Oracle Secure Global Desktop";
version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

fix_required = NULL;

if (version =~ "^5\.10($|\.)") fix_required = 'Patch_51p5';
else if (version =~ "^5\.00($|\.)") fix_required = 'Patch_50p5';
else if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p5';
else if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p5';

if (isnull(fix_required)) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version);

patches = get_kb_list("Host/Oracle_Secure_Global_Desktop/Patches");

patched = FALSE;
foreach patch (patches)
{
  if (patch == fix_required)
  {
    patched = TRUE;
    break;
  }
}

if (patched) audit(AUDIT_INST_VER_NOT_VULN, app, version + ' (with ' + fix_required + ')');

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Patch required    : ' + fix_required +
           '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
