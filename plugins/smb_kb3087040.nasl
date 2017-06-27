#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86065);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id(
    "CVE-2015-5567",
    "CVE-2015-5568",
    "CVE-2015-5570",
    "CVE-2015-5571",
    "CVE-2015-5572",
    "CVE-2015-5573",
    "CVE-2015-5574",
    "CVE-2015-5575",
    "CVE-2015-5576",
    "CVE-2015-5577",
    "CVE-2015-5578",
    "CVE-2015-5579",
    "CVE-2015-5580",
    "CVE-2015-5581",
    "CVE-2015-5582",
    "CVE-2015-5584",
    "CVE-2015-5587",
    "CVE-2015-5588",
    "CVE-2015-6676",
    "CVE-2015-6677",
    "CVE-2015-6678",
    "CVE-2015-6679",
    "CVE-2015-6682"
  );
  script_osvdb_id(
    127803,
    127804,
    127805,
    127806,
    127807,
    127808,
    127809,
    127810,
    127811,
    127812,
    127813,
    127814,
    127815,
    127816,
    127817,
    127818,
    127819,
    127820,
    127821,
    127822,
    127823,
    127824,
    127825
  );

  script_name(english:"MS KB3087040: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer and Microsoft Edge");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3087040. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified stack corruption issue exists that
    allows a remote attacker to execute arbitrary code.
    (CVE-2015-5567, CVE-2015-5579)

  - A vector length corruption issue exists that allows a
    remote attacker to have an unspecified impact.
    (CVE-2015-5568)

  - A use-after-free error exists in an unspecified
    component due to improperly sanitized user-supplied
    input. A remote attacker can exploit this, via a
    specially crafted file, to deference already freed
    memory and execute arbitrary code. (CVE-2015-5570,
    CVE-2015-5574, CVE-2015-5581, CVE-2015-5584,
    CVE-2015-6682)

  - An unspecified flaw exists due to a failure to reject
    content from vulnerable JSONP callback APIs. A remote
    attacker can exploit this to have an unspecified impact.
    (CVE-2015-5571)

  - An unspecified flaw exists that allows a remote attacker
    to bypass security restrictions and gain access to
    sensitive information. (CVE-2015-5572)

  - An unspecified type confusion flaw exists that allows a
    remote attacker to execute arbitrary code.
    (CVE-2015-5573)

  - A flaw exists in an unspecified component due to
    improper validation of user-supplied input when handling
    a specially crafted file. A remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    or the execution of arbitrary code. (CVE-2015-5575,
    CVE-2015-5577, CVE-2015-5578, CVE-2015-5580,
    CVE-2015-5582, CVE-2015-5588, CVE-2015-6677)

  - A memory leak issue exists that allows a remote
    attacker to have an unspecified impact. (CVE-2015-5576)

  - A stack buffer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-5587)

  - An unspecified overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-6676,
    CVE-2015-6678)

  - An unspecified flaw exists that allows a remote attacker
    to bypass same-origin policy restrictions and gain
    access to sensitive information. (CVE-2015-6679)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-23.html");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3087040");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB3087040.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
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

# <= 18.0.0.232, Published fix is 19.0.0.185
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 18 ||
    (
      iver[0] == 18 &&
      (
        (iver[1] == 0 && iver[2] == 0 && iver[3] <= 232)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 19.0.0.185' +
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
