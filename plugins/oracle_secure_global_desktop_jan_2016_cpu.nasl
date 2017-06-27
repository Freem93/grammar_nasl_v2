#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88049);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id(
    "CVE-2015-3183",
    "CVE-2015-4000",
    "CVE-2016-0501"
  );
  script_bugtraq_id(
    74733, 
    75963
  );
  script_osvdb_id(
    122331,
    123122,
    133374
  );

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (January 2016 CPU) (Logjam)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Secure Global Desktop installed on the remote
host is version 4.63 / 4.71 / 5.2 and is missing a security patch from
the January 2016 Critical Patch Update (CPU). It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists in the bundled version of Apache HTTP
    Server in the chunked transfer coding implementation due
    to a failure to properly parse chunk headers. A remote
    attacker can exploit this to conduct HTTP request
    smuggling attacks. (CVE-2015-3183)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - An unspecified flaw exists in the SGD Core subcomponent
    that allows a remote attacker to cause a denial of
    service condition. (CVE-2016-0501)");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1a16c5");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (version =~ "^5\.20($|\.)") fix_required = 'Patch_52p3';
else if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p8';
else if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p8';

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
  security_warning(port:0, extra:report);
}
else security_warning(0);
