#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55144);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2011-2094",
    "CVE-2011-2095",
    "CVE-2011-2096",
    "CVE-2011-2097",
    "CVE-2011-2098",
    "CVE-2011-2099",
    "CVE-2011-2100",
    "CVE-2011-2101",
    "CVE-2011-2102",
    "CVE-2011-2103",
    "CVE-2011-2104",
    "CVE-2011-2105"
  );
  script_bugtraq_id(
    48240,
    48242,
    48243,
    48244,
    48245,
    48246,
    48247,
    48248,
    48251,
    48252,
    48253,
    48255
  );
  script_osvdb_id(
    73055,
    73056,
    73057,
    73058,
    73059,
    73061,
    73062,
    73063,
    73064,
    73065,
    73066,
    73067
  );

  script_xref(name:"CERT", value:"264729");

  script_name(english:"Adobe Reader < 10.1 / 9.4.5 / 8.3 Multiple Vulnerabilities (APSB11-16)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Reader installed on the remote host is earlier
than 10.1 / 9.4.5 / 8.3.  Such versions are reportedly affected by
multiple vulnerabilities :

  - Multiple buffer overflow vulnerabilities exist that
    could lead to code execution. (CVE-2011-2094,
    CVE-2011-2095, CVE-2011-2097)

  - A heap overflow vulnerability exists that could lead to
    code execution. (CVE-2011-2096)

  - Multiple memory corruption vulnerabilities exist that
    could lead to code execution. (CVE-2011-2098,
    CVE-2011-2099, CVE-2011-2103, CVE-2011-2105)

  - Multiple memory corruption vulnerabilities exist that
    could cause the application to crash. (CVE-2011-2104,
    CVE-2011-2105)

  - A DLL loading vulnerability exists that could lead to
    code execution. (CVE-2011-2100)

  - A cross document script execution vulnerability exists
    that could lead to code execution. (CVE-2011-2101)

  - A security bypass vulnerability exists that could lead
    to bypassing security restrictions. (CVE-2011-2102)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-218");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-219");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-16.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 8.3 / 9.4.5 / 10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

info = "";
info2 = "";
vuln = 0;

vers = get_kb_list("SMB/Acroread/Version");
if (isnull(vers)) exit(0, "The 'SMB/Acroread/Version' KB list is missing.");

foreach version (vers)
{
  ver = split(version, sep:".", keep:FALSE);
  for (i = 0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item("SMB/Acroread/" + version + "/Path");
  if (isnull(path)) path = "n/a";

  verui = get_kb_item("SMB/Acroread/" + version + "/Version_UI");
  if (isnull(verui)) verui = version;

  if (
    (ver[0] < 8) ||
    (ver[0] == 8 && ver[1] < 3) ||
    (ver[0] == 9 && ver[1] < 4) ||
    (ver[0] == 9 && ver[1] == 4 && ver[2] < 5) ||
    (ver[0] == 10 && ver[1] < 1)
  )
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + verui +
      '\n  Fixed version     : 8.3 / 9.4.5 / 10.1' +
      '\n';
  }
  else info2 += " and " + verui;
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Reader are";
    else s = " of Adobe Reader is";

    report =
      '\nThe following vulnerable instance' + s + ' installed on the' +
      '\nremote host :' +
      '\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}

if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Reader " + info2 + " " + be + " installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
