#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84052);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id(
    "CVE-2015-3096",
    "CVE-2015-3097",
    "CVE-2015-3098",
    "CVE-2015-3099",
    "CVE-2015-3100",
    "CVE-2015-3101",
    "CVE-2015-3102",
    "CVE-2015-3103",
    "CVE-2015-3104",
    "CVE-2015-3105",
    "CVE-2015-3106",
    "CVE-2015-3107",
    "CVE-2015-3108"
  );
  script_bugtraq_id(
    75080,
    75081,
    75084,
    75085,
    75086,
    75087,
    75088,
    75089,
    75090
  );
  script_osvdb_id(
    123020,
    123021,
    123022,
    123023,
    123024,
    123025,
    123026,
    123027,
    123028,
    123029,
    123030,
    123031,
    123032
  );

  script_name(english:"MS KB3065820: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3065820. It is, therefore,
affected by the multiple vulnerabilities :

  - An unspecified vulnerability exists that allows an
    attacker to bypass the fix for CVE-2014-5333.
    (CVE-2015-3096)

  - An unspecified memory address randomization flaw exists
    on Windows 7 64-bit. (CVE-2015-3097)

  - Multiple unspecified flaws exist that allow a remote
    attacker to bypass the same-origin-policy, resulting in
    the disclosure of sensitive information. (CVE-2015-3098,
    CVE-2015-3099, CVE-2015-3102)

  - A remote code execution vulnerability exists due to an
    unspecified stack overflow flaw. (CVE-2015-3100)

  - A permission flaw exists in the Flash broker for IE
    that allows an attacker to perform a privilege
    escalation. (CVE-2015-3101)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-3103,
    CVE-2015-3106, CVE-2015-3107)

  - An integer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-3104)

  - A memory corruption flaw exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this flaw, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-3105)

  - An unspecified memory leak exists that allows an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-3108)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2755801");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/kb/3065820");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-11.html");
  script_set_attribute(attribute:"solution", value:
"Install Microsoft KB3065820.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Drawing Fill Shader Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

# <= 17.0.0.188
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 17 ||
    (
      iver[0] == 17 &&
      (
        (iver[1] == 0 && iver[2] == 0 && iver[3] <= 188)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 18.0.0.160' +
         '\n';
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
