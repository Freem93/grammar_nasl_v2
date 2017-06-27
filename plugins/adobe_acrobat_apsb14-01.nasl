#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71946);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:21:27 $");

  script_cve_id("CVE-2014-0493", "CVE-2014-0495", "CVE-2014-0496");
  script_bugtraq_id(64802, 64803, 64804);
  script_osvdb_id(101979, 101980, 101981);

  script_name(english:"Adobe Acrobat < 10.1.9 / 11.0.6 Multiple Vulnerabilities (APSB14-01)");
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
"The version of Adobe Acrobat installed on the remote host is a version
prior to 10.1.9 / 11.0.6.  It is, therefore, affected by multiple
vulnerabilities :

  - Memory corruption vulnerabilities exist that could lead
    to code execution. (CVE-2014-0493, CVE-2014-0495)

  - A use-after-free vulnerability exists that could lead to
    code execution. (CVE-2014-0496)"
  );
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb14-01.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 10.1.9 / 11.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Acrobat/Version");
version_ui = get_kb_item("SMB/Acrobat/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

path = get_kb_item_or_exit("SMB/Acrobat/Path");

if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 9) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] < 6)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 11.0.6 / 10.1.9\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe Acrobat", version_report, path);
