#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66409);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2013-2549",
    "CVE-2013-2550",
    "CVE-2013-2718",
    "CVE-2013-2719",
    "CVE-2013-2720",
    "CVE-2013-2721",
    "CVE-2013-2722",
    "CVE-2013-2723",
    "CVE-2013-2724",
    "CVE-2013-2725",
    "CVE-2013-2726",
    "CVE-2013-2727",
    "CVE-2013-2729",
    "CVE-2013-2730",
    "CVE-2013-2731",
    "CVE-2013-2732",
    "CVE-2013-2733",
    "CVE-2013-2734",
    "CVE-2013-2735",
    "CVE-2013-2736",
    "CVE-2013-2737",
    "CVE-2013-3337",
    "CVE-2013-3338",
    "CVE-2013-3339",
    "CVE-2013-3340",
    "CVE-2013-3341",
    "CVE-2013-3342",
    "CVE-2013-3346"
  );
  script_bugtraq_id(
    58398,
    58568,
    59902,
    59903,
    59904,
    59905,
    59906,
    59907,
    59908,
    59909,
    59910,
    59911,
    59912,
    59913,
    59914,
    59915,
    59916,
    59917,
    59918,
    59919,
    59920,
    59921,
    59923,
    59925,
    59926,
    59927,
    59930,
    62149
  );
  script_osvdb_id(
    91201,
    91202,
    93335,
    93336,
    93337,
    93338,
    93339,
    93340,
    93341,
    93342,
    93343,
    93344,
    93345,
    93346,
    93347,
    93348,
    93349,
    93350,
    93351,
    93352,
    93353,
    93354,
    93355,
    93356,
    93357,
    93358,
    93359,
    96745
  );
  script_xref(name:"EDB-ID", value:"26703");

  script_name(english:"Adobe Acrobat < 11.0.3 / 10.1.7 / 9.5.5 Multiple Vulnerabilities (APSB13-15)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Adobe Acrobat installed on the remote Windows host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 11.0.3 / 10.1.7 / 9.5.5.  It is, therefore, affected by multiple
vulnerabilities :

  - Unspecified memory corruption vulnerabilities exist that
    could lead to code execution. (CVE-2013-2718,
    CVE-2013-2719, CVE-2013-2720, CVE-2013-2721,
    CVE-2013-2722, CVE-2013-2723, CVE-2013-2725,
    CVE-2013-2726, CVE-2013-2731, CVE-2013-2732,
    CVE-2013-2734, CVE-2013-2735, CVE-2013-2736,
    CVE-2013-3337, CVE-2013-3338, CVE-2013-3339,
    CVE-2013-3340, CVE-2013-3341, CVE-2013-3346)

  - An integer underflow error exists that could lead to
    code execution. (CVE-2013-2549)

  - A use-after-free error exists that could lead to a
    bypass of Adobe Reader's sandbox protection.
    (CVE-2013-2550)

  - An unspecified information leakage issue involving a
    JavaScript API exists.  (CVE-2013-2737)

  - An unspecified stack overflow issue exists that could
    lead to code execution. (CVE-2013-2724)

  - An unspecified buffer overflow error exists that could
    lead to code execution. (CVE-2013-2730, CVE-2013-2733)

  - An unspecified integer overflow error exists that could
    lead to code execution. (CVE-2013-2727, CVE-2013-2729)

  - A flaw exists in the way Reader handles domains that
    have been blacklisted in the operating system.
    (CVE-2013-3342)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-105/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-106/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-212/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-15.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 11.0.3 / 10.1.7 / 9.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Reader ToolButton Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.');

  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('SMB/Acrobat/Version');
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Acrobat/Version");
version_ui = get_kb_item('SMB/Acrobat/Version_UI');

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

path = get_kb_item_or_exit('SMB/Acrobat/Path');

if (
  (ver[0] == 9 && ver[1] < 5) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 5) ||
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 7) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] < 3)
)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 11.0.3 / 10.1.7 / 9.5.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe Acrobat", version_report, path);
