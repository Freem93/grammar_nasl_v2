#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64587);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:11:37 $");

  script_cve_id(
    "CVE-2013-0637",
    "CVE-2013-0638",
    "CVE-2013-0639",
    "CVE-2013-0642",
    "CVE-2013-0644",
    "CVE-2013-0645",
    "CVE-2013-0647",
    "CVE-2013-0649",
    "CVE-2013-1365",
    "CVE-2013-1366",
    "CVE-2013-1367",
    "CVE-2013-1368",
    "CVE-2013-1369",
    "CVE-2013-1370",
    "CVE-2013-1372",
    "CVE-2013-1373",
    "CVE-2013-1374"
  );
  script_bugtraq_id(
    57912,
    57916,
    57917,
    57918,
    57919,
    57920,
    57921,
    57922,
    57923,
    57924,
    57925,
    57926,
    57927,
    57929,
    57930,
    57932,
    57933
  );
  script_osvdb_id(
    90095,
    90096,
    90097,
    90098,
    90099,
    90100,
    90101,
    90102,
    90103,
    90104,
    90105,
    90106,
    90107,
    90108,
    90109,
    90110,
    90111
  );

  script_name(english:"MS KB2805940: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer 10");
  script_summary(english:"Checks version of ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has a vulnerable ActiveX control installed."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing KB2805940.  The installed version of Adobe
Flash ActiveX control is potentially affected by the following
vulnerabilities :

  - Several unspecified issues exist that could lead to
    buffer overflows and arbitrary code execution.
    (CVE-2013-1372, CVE-2013-0645, CVE-2013-1373,
    CVE-2013-1369, CVE-2013-1370, CVE-2013-1366,
    CVE-2013-1365, CVE-2013-1368, CVE-2013-0642,
    CVE-2013-1367)

  - Several unspecified use-after-free vulnerabilities exist
    that could lead to remote code execution. (CVE-2013-0649,
    CVE-2013-1374, CVE-2013-0644)

  - Two unspecified issues exist that could lead to memory
    corruption and arbitrary code execution. (CVE-2013-0638,
    CVE-2013-0647)

  - An unspecified information disclosure vulnerability
    exists. (CVE-2013-0637)

  - An unspecified integer overflow vulnerability exists.
    (CVE-2013-0639)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-05.html");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2805940");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2805940.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
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
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init()");

# Adobe Flash Player CLSID
clsid = '{D27CDB6E-AE6D-11CF-96B8-444553540000}';

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

# < 11.6.602.167
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 11 ||
    (
      iver[0] == 11 &&
      (
        iver[1] < 6 ||
        (iver[1] == 6 && iver[2] < 602) ||
        (iver[1] == 6 && iver[2] == 602 && iver[3] < 167)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 11.6.602.167\n';
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
