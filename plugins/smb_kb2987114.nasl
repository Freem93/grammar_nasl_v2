#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77580);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id(
    "CVE-2014-0547",
    "CVE-2014-0548",
    "CVE-2014-0549",
    "CVE-2014-0550",
    "CVE-2014-0551",
    "CVE-2014-0552",
    "CVE-2014-0553",
    "CVE-2014-0554",
    "CVE-2014-0555",
    "CVE-2014-0556",
    "CVE-2014-0557",
    "CVE-2014-0559"
  );
    script_bugtraq_id(
    69695,
    69696,
    69697,
    69699,
    69700,
    69701,
    69702,
    69703,
    69704,
    69705,
    69706,
    69707
  );
  script_osvdb_id(
    111100,
    111101,
    111102,
    111103,
    111104,
    111105,
    111106,
    111107,
    111108,
    111109,
    111110,
    111111
  );

  script_name(english:"MS KB2987114: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer");
  script_summary(english:"Checks version of ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an ActiveX control installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB2987114. It is, therefore, affected by
the following vulnerabilities :

  - Unspecified memory corruption issues exist that allow
    arbitrary code execution. (CVE-2014-0547, CVE-2014-0549,
    CVE-2014-0550, CVE-2014-0551, CVE-2014-0552,
    CVE-2014-0555)

  - An unspecified error exists that allows cross-origin
    policy violations. (CVE-2014-0548)

  - A use-after-free error exists that allows arbitrary
    code execution. (CVE-2014-0553)

  - An unspecified error exists that allows an unspecified
    security bypass. (CVE-2014-0554)

  - Unspecified errors exist that allow memory leaks leading
    to easier defeat of memory address randomization.
    (CVE-2014-0557)

  - Heap-based buffer overflow errors exist that allow
    arbitrary code execution. (CVE-2014-0556, CVE-2014-0559)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-21.html");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/2755801");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/kb/2987114");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2987114.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player copyPixelsToByteArray Method Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init()");

# Adobe Flash Player CLSID
clsid = '{D27CDB6E-AE6D-11cf-96B8-444553540000}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, "activex_get_filename", "NULL");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

info = '';

iver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
 iver[i] = int(iver[i]);

# < 15.0.0.152
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 15 ||
    (
      iver[0] == 15 &&
      (
        (iver[1] == 0 && iver[2] == 0 && iver[3] < 152)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 15.0.0.152\n';
}

port = kb_smb_transport();

if (info != '')
{
  if (report_verbosity > 0)
  {
    if (report_paranoia > 1)
    {
      report = info +
        '\n' +
        'Note, though, that Nessus did not check whether the kill bit was\n' +
        "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
        'in effect when this scan was run.\n';
    }
    else
    {
      report = info +
        '\n' +
        'Moreover, its kill bit is not set so it is accessible via Internet\n' +
        'Explorer.\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, 'affected');
