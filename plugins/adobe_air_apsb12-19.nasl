#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61624);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2012-4163",
    "CVE-2012-4164",
    "CVE-2012-4165",
    "CVE-2012-4167",
    "CVE-2012-4168",
    "CVE-2012-4171"
  );
  script_bugtraq_id(55365);
  script_osvdb_id(84789, 84790, 84791, 84793, 84794, 85260);

  script_name(english:"Adobe AIR 3.x <= 3.3.0.3670 Multiple Vulnerabilities (APSB12-19)");
  script_summary(english:"Checks version gathered by local check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Adobe AIR on the remote
Windows host is 3.3.0.3670 or earlier and is, therefore, reportedly
affected by multiple vulnerabilities :

  - Multiple memory corruption vulnerabilities could lead to
    code execution. (CVE-2012-4163, CVE-2012-4164,
    CVE-2012-4165)

  - An integer overflow vulnerability exists that could
    lead to code execution. (CVE-2012-4167)

  - A cross-domain information leak vulnerability exists.
    (CVE-2012-4168)

  - A crash can be caused by a logic error involving
    multiple dialogs in Firefox. (CVE-2012-4171)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-19.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 3.4 (3.4.0.2540) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");


  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

cutoff_version = '3.3.0.3670';
fix = '3.4.0.2540';
fix_ui = '3.4';

if (version =~ '^3\\.' && ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
