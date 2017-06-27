#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77711);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/04/27 14:49:38 $");

  script_cve_id(
    "CVE-2014-0560",
    "CVE-2014-0561",
    "CVE-2014-0563",
    "CVE-2014-0565",
    "CVE-2014-0566",
    "CVE-2014-0567",
    "CVE-2014-0568",
    "CVE-2014-9150"
  );
  script_bugtraq_id(
    69823,
    69821,
    69826,
    69824,
    69825,
    69827,
    69828,
    71366
  );
  script_osvdb_id(
    111533,
    111536,
    111535,
    111538,
    111539,
    111537,
    111540
  );

  script_name(english:"Adobe Acrobat < 10.1.12 / 11.0.09 Multiple Vulnerabilities (APSB14-20)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote host is a version
prior to 10.1.12 / 11.0.09. It is, therefore, affected by the
following vulnerabilities :

  - A use-after-free error exists that allows arbitrary code
    execution. (CVE-2014-0560)

  - A heap-based buffer overflow exists that allows
    arbitrary code execution. (CVE-2014-0561, CVE-2014-0567)

  - A memory corruption error exists that allows denial of
    service attacks. (CVE-2014-0563)

  - Memory corruption errors exist that allows arbitrary
    code execution. (CVE-2014-0565, CVE-2014-0566)

  - An unspecified error exists that allows the bypassing
    of the sandbox security restrictions. (CVE-2014-0568)

  - A race condition exists in the 'MoveFileEx' call hook
    feature that allows attackers to bypass the sandbox
    protection mechanism to write files to arbitrary
    locations. Note that this issue only affects Adobe
    Acrobat 11.x. This issue has not been officially fixed
    in APSB14-20; however, it is unlikely to be exploitable
    due to a related defense-in-depth change in version
    11.0.09. (CVE-2014-9150)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/reader/apsb14-20.html");
  # https://code.google.com/p/google-security-research/issues/detail?id=103
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9107f739");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 10.1.12 / 11.0.09 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Acrobat";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];
verui   = install['display_version'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 12) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] < 9)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : '+path+
             '\n  Installed version : '+verui+
             '\n  Fixed version     : 10.1.12 / 11.0.09' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);
