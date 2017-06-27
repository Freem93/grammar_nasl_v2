#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86904);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id(
    "CVE-2015-1774",
    "CVE-2015-4551",
    "CVE-2015-5212",
    "CVE-2015-5213",
    "CVE-2015-5214"
  );
  script_osvdb_id(
    121343,
    129859,
    129856,
    129857,
    129858
  );

  script_name(english:"Apache OpenOffice < 4.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a
version prior to 4.1.2. It is, therefore, affected by the following
vulnerabilities :

  - An overflow condition exists in the Hangul Word
    Processor (HWP) filter due to improper validation of
    user-supplied input. A remote attacker can exploit this,
    via a specially crafted HWP document, to cause a denial
    of service condition or the execution of arbitrary code.
    (CVE-2015-1774)

  - An information disclosure vulnerability exists due to
    the use of stored LinkUpdateMode configuration
    information in OpenDocument Format files and templates
    when handling links. A remote attacker can exploit this,
    via a specially crafted ODF document, to to obtain
    sensitive information. (CVE-2015-4551)

  - An integer underflow condition exists in the
    ReadJobSetup() function due to improper validation of
    user-supplied input when handling printer settings. A
    remote attacker can exploit this, via specially crafted
    PrinterSetup data in an ODF document, to cause a denial
    of service condition or the execution of arbitrary code.
    (CVE-2015-5212)

  - An integer underflow condition exists in the
    WW8ScannerBase::OpenPieceTable() function due to
    improper validation of user-supplied input when handling
    the PieceTable counter. A remote attacker can exploit
    this, via a specially crafted .DOC file, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2015-5213)

  - A memory corruption issue exists in
    'filter/ww8/ww8scan.cxx' due to improper validation of
    user-supplied input when handling bookmark status
    positions. A remote attacker can exploit this, via a
    specially crafted document, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-5214)");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2015-1774.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2015-4551.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2015-5212.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2015-5213.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2015-5214.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name   = "OpenOffice";

get_kb_item_or_exit("SMB/Registry/Enumerated");

install    = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
build      = install['version'];
path       = install['path'];
version_ui = install['display_version'];

matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
if (isnull(matches)) audit(AUDIT_VER_FAIL, app_name);

buildid = int(matches[2]);
if (buildid < 9782)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.1.2 (412m3 / build 9782)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui, path);
