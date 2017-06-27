#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69845);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/01/19 03:39:41 $");

  script_cve_id(
    "CVE-2013-3351",
    "CVE-2013-3352",
    "CVE-2013-3353",
    "CVE-2013-3354",
    "CVE-2013-3355",
    "CVE-2013-3356",
    "CVE-2013-3357",
    "CVE-2013-3358"
  );
  script_bugtraq_id(
    62428,
    62429,
    62430,
    62431,
    62432,
    62433,
    62435,
    62436
  );
  script_osvdb_id(
    97054,
    97055,
    97056,
    97057,
    97058,
    97059,
    97060,
    97061
  );

  script_name(english:"Adobe Acrobat < 11.0.4 / 10.1.8 Multiple Vulnerabilities (APSB13-22)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(
    attribute:"synopsis",

    value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 11.0.4 / 10.1.8.  It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified stack overflow issue exists that could
    lead to code execution. (CVE-2013-3351)

  - Unspecified memory corruption vulnerabilities exist that
    could lead to code execution. (CVE-2013-3352,
    CVE-2013-3354, CVE-2013-3355)

  - Unspecified buffer overflow errors exist that could
    lead to code execution. (CVE-2013-3353, CVE-2013-3356)

  - Unspecified integer overflow errors exist that could
    lead to code execution. (CVE-2013-3357, CVE-2013-3358)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-230/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-22.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 11.0.4 / 10.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.');

  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('SMB/Acrobat/Version');
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit("SMB/Acrobat/Version");
version_ui = get_kb_item('SMB/Acrobat/Version_UI');

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

path = get_kb_item_or_exit('SMB/Acrobat/Path');

if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 8) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] < 4)
)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 11.0.4 / 10.1.8\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe Acrobat", version_report, path);
