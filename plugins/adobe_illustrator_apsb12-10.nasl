#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59179);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/18 04:28:24 $");

  script_cve_id(
    "CVE-2012-0780",
    "CVE-2012-2023",
    "CVE-2012-2024",
    "CVE-2012-2025",
    "CVE-2012-2026",
    "CVE-2012-2042"
  );
  script_bugtraq_id(53422);
  script_osvdb_id(81754, 81755, 81756, 81757, 81758, 82404);
  script_xref(name:"EDB-ID", value:"19139");

  script_name(english:"Adobe Illustrator CS5 / CS5.5 Multiple Memory Corruption Vulnerabilities (APSB12-10)");
  script_summary(english:"Checks version of Adobe Illustrator");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application affected by multiple
memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Adobe Illustrator less
than CS5 15.0.3 / CS5.5 15.1.1.  As such, it reportedly is affected by
multiple unspecified memory corruption vulnerabilities that could be 
exploited to execute arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-10.html");
  script_set_attribute(
    attribute:"solution", 
    value:
"Either upgrade to Adobe Illustrator CS6 (16.0) or apply the update
for CS5 (15.0.3) or CS5.5 (15.1.1).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

appname = "Adobe Illustrator";
version = get_kb_item_or_exit("SMB/Adobe Illustrator/version");
path = get_kb_item_or_exit("SMB/Adobe Illustrator/path");
prod = get_kb_item_or_exit("SMB/Adobe Illustrator/product");

ver = split(version, sep:'.', keep:FALSE);

if (
  ver[0] < 15 ||
  (
    ver[0] == 15 &&
    (
      (ver[1] == 0 && ver[2] < 3) ||
      (ver[1] == 1 && ver[2] < 1)
    )
  )
) 
{
  if (ver[0] == 15 && ver[1] == 0) fix = "CS5 (15.0.3) / CS6 (16.0)";
  else if (ver[0] == 15 && ver[1] == 1)  fix = "CS5.5 (15.1.1) / CS6 (16.0)";
  else fix = "CS6 (16.0)";

  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report = 
      '\n  Product           : ' + prod + 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
