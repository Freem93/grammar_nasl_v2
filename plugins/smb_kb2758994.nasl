#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62467);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id(
    "CVE-2012-5248",
    "CVE-2012-5249",
    "CVE-2012-5250",
    "CVE-2012-5251",
    "CVE-2012-5252",
    "CVE-2012-5253",
    "CVE-2012-5254",
    "CVE-2012-5255",
    "CVE-2012-5256",
    "CVE-2012-5257",
    "CVE-2012-5258",
    "CVE-2012-5259",
    "CVE-2012-5260",
    "CVE-2012-5261",
    "CVE-2012-5262",
    "CVE-2012-5263",
    "CVE-2012-5264",
    "CVE-2012-5265",
    "CVE-2012-5266",
    "CVE-2012-5267",
    "CVE-2012-5268",
    "CVE-2012-5269",
    "CVE-2012-5270",
    "CVE-2012-5271",
    "CVE-2012-5272",
    "CVE-2012-5285",
    "CVE-2012-5286",
    "CVE-2012-5287",
    "CVE-2012-5673"
  );
  script_bugtraq_id(
    56198,
    56200,
    56201,
    56202,
    56203,
    56204,
    56205,
    56206,
    56207,
    56208,
    56209,
    56210,
    56211,
    56212,
    56213,
    56214,
    56215,
    56216,
    56217,
    56218,
    56219,
    56220,
    56221,
    56222,
    56224,
    56374,
    56375,
    56376,
    56377
  );
  script_osvdb_id(
    86025,
    86026,
    86027,
    86028,
    86029,
    86030,
    86031,
    86032,
    86033,
    86034,
    86035,
    86036,
    86037,
    86038,
    86039,
    86040,
    86041,
    86042,
    86043,
    86044,
    86045,
    86046,
    86047,
    86048,
    86049,
    86874,
    86875,
    86876,
    86877
  );
  script_name(english:"MS KB2758994: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer 10");
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
"The remote host is missing KB2758994.  It may, therefore, be affected
by the following vulnerabilities related to the installed version of the
Adobe Flash ActiveX control :

  - Multiple memory corruption errors exist that
    could lead to code execution. (CVE-2012-5248,
    CVE-2012-5249, CVE-2012-5250, CVE-2012-5251,
    CVE-2012-5252, CVE-2012-5256, CVE-2012-5258,
    CVE-2012-5261, CVE-2012-5263, CVE-2012-5267,
    CVE-2012-5268, CVE-2012-5269, CVE-2012-5270,
    CVE-2012-5271, CVE-2012-5272)

  - Multiple buffer overflow errors exist that
    could lead to code execution. (CVE-2012-5248,
    CVE-2012-5249, CVE-2012-5250, CVE-2012-5251,
    CVE-2012-5253, CVE-2012-5254, CVE-2012-5255,
    CVE-2012-5257, CVE-2012-5259, CVE-2012-5260,
    CVE-2012-5262, CVE-2012-5264, CVE-2012-5265,
    CVE-2012-5266, CVE-2012-5285, CVE-2012-5286,
    CVE-2012-5287)

  - An unspecified issue exists having unspecified impact.
    (CVE-2012-5673)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-22.html");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2755801");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2758994");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2758994.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

# < 11.3.375.10
if( (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
    (iver[0] < 11 ||
      (iver[0] == 11 &&
        (iver[1] < 3 ||
          (iver[1] == 3 && iver[2] < 375) ||
          (iver[1] == 3 && iver[2] == 375 && iver[3] < 10)
        )
      )
    )
  )
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 11.3.375.10\n';
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
