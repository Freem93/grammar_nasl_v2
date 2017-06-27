#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48299);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/05 14:31:49 $");

  script_cve_id(
    "CVE-2010-0209",
    "CVE-2010-2188",
    "CVE-2010-2213",
    "CVE-2010-2214",
    "CVE-2010-2215",
    "CVE-2010-2216"
  );
  script_bugtraq_id(40798, 42358, 42361, 42362, 42363, 42364);
  script_osvdb_id(65599, 67057, 67058, 67059, 67060, 67061, 67062);
  script_xref(name:"CERT", value:"660993");

  script_name(english:"Adobe AIR < 2.0.3 Multiple Vulnerabilities (APSB10-16)");
  script_summary(english:"Checks version of Adobe AIR");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe AIR that is
earlier than 2.0.3.  Such versions are affected by multiple memory
corruption issues and a click-jacking vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb10-16.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe AIR 2.0.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

fix = '2.0.3.0';
fix_ui = '2.0.3';

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The Adobe AIR "+version_report+" install is not affected.");
