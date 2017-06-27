#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73418);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_cve_id(
    "CVE-2014-0506",
    "CVE-2014-0507",
    "CVE-2014-0508",
    "CVE-2014-0509"
  );
  script_bugtraq_id(66208, 66699, 66701, 66703);
  script_osvdb_id(104598, 105535, 105536, 105537);

  script_name(english:"MS KB2942844: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer");
  script_summary(english:"Checks version of ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an ActiveX control installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB2942844. It is, therefore, affected by
the following vulnerabilities :

  - A use-after-free error exists that could lead to
    arbitrary code execution. (CVE-2014-0506)

  - A buffer overflow error exists that could lead to
    arbitrary code execution. (CVE-2014-0507)

  - An unspecified error exists that could allow a security
    bypass leading to information disclosure.
    (CVE-2014-0508)

  - An unspecified error exists that could allow cross-
    site scripting attacks. (CVE-2014-0509)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-09.html");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/security/advisory/2755801");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2942844");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2942844.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

# < 13.0.0.182
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 13 ||
    (
      iver[0] == 13 &&
      (
        (iver[1] == 0 && iver[2] == 0 && iver[3] < 182)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 13.0.0.182\n';
}

port = kb_smb_transport();

if (info != '')
{
  # XSS
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

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
