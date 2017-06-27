#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86371);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id(
    "CVE-2015-5569",
    "CVE-2015-7625",
    "CVE-2015-7626",
    "CVE-2015-7627",
    "CVE-2015-7628",
    "CVE-2015-7629",
    "CVE-2015-7630",
    "CVE-2015-7631",
    "CVE-2015-7632",
    "CVE-2015-7633",
    "CVE-2015-7634",
    "CVE-2015-7643",
    "CVE-2015-7644"
  );
  script_osvdb_id(
    128762,
    128763,
    128764,
    128765,
    128766,
    128767,
    128768,
    128769,
    128770,
    128771,
    128772,
    128773,
    128774
  );

  script_name(english:"MS KB3099406: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer and Microsoft Edge");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3099406. It is, therefore,
affected by multiple vulnerabilities :

  - An unspecified vulnerability exists related to the
    defense-in-depth feature in the Flash Broker API. No
    other details are available. (CVE-2015-5569)

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-7625, CVE-2015-7626, CVE-2015-7627,
    CVE-2015-7630, CVE-2015-7633, CVE-2015-7634)

  - A unspecified vulnerability exists that can be exploited
    by a remote attacker to bypass the same-origin policy,
    allowing the disclosure of sensitive information.
    (CVE-2015-7628)

  - Multiple unspecified use-after-free errors exist that
    can be exploited by a remote attacker to deference
    already freed memory, potentially allowing the
    execution of arbitrary code. (CVE-2015-7629,
    CVE-2015-7631, CVE-2015-7643, CVE-2015-7644)

  - An unspecified buffer overflow condition exists due to
    improper validation of user-supplied input. An attacker
    can exploit this to execute arbitrary code.
    (CVE-2015-7632)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-25.html");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3099406");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB3099406.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
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
iver = join(iver, sep:".");

# all < 18.0.0.252 or 19 < 19.0.0.207
fix = FALSE;
if(iver =~ "^19\." && ver_compare(ver:iver, fix:"19.0.0.207", strict:FALSE) < 0)
  fix = "19.0.0.207";
else if(ver_compare(ver:iver, fix:"18.0.0.252", strict:FALSE) < 0)
  fix = "18.0.0.252";

if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  fix
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : ' + fix +
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
