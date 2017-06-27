#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63231);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/12/06 11:41:12 $");

  script_cve_id("CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678");
  script_bugtraq_id(56892, 56896, 56898);
  script_osvdb_id(88353, 88354, 88356);

  script_name(english:"MS KB2785605: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer 10");
  script_summary(english:"Checks version of ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control installed with multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing KB2785605.  It may, therefore, be affected
by the following vulnerabilities related to the installed version of the
Adobe Flash ActiveX control :

  - An unspecified error exists that could allow a buffer
    overflow and arbitrary code execution. (CVE-2012-5676)

  - An unspecified error exists that could allow an integer
    overflow and arbitrary code execution. (CVE-2012-5677)

  - An unspecified error exists that could lead to memory
    corruption and arbitrary code execution. (CVE-2012-5678)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-021/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-27.html");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2785605");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2755801");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2785605.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK)
  audit(AUDIT_FN_FAIL, "activex_init()");

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

# < 11.3.377.15
if( (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
    (iver[0] < 11 ||
      (iver[0] == 11 &&
        (iver[1] < 3 ||
          (iver[1] == 3 && iver[2] < 377) ||
          (iver[1] == 3 && iver[2] == 377 && iver[3] < 15)
        )
      )
    )
  )
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 11.3.377.15\n';
}

port = kb_smb_transport();

if(info != '')
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
