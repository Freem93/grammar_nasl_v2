#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(1);


include("compat.inc");


if (description)
{
  script_id(47888);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id(
    "CVE-2010-1778",
    "CVE-2010-1780",
    "CVE-2010-1782",
    "CVE-2010-1783",
    "CVE-2010-1784",
    "CVE-2010-1785",
    "CVE-2010-1786",
    "CVE-2010-1787",
    "CVE-2010-1788",
    "CVE-2010-1789",
    "CVE-2010-1790",
    "CVE-2010-1791",
    "CVE-2010-1792",
    "CVE-2010-1793",
    "CVE-2010-1796"
  );
  script_bugtraq_id(
    41884,
    42034,
    42035, 
    42036,
    42037,
    42038,
    42039,
    42041,
    42042,
    42043,
    42044,
    42045,
    42046,
    42048,
    42049
  );
  script_osvdb_id(
    66513,
    66844,
    66845,
    66846,
    66847,
    66848,
    66849,
    66850,
    66851,
    66852,
    66853,
    66854,
    66855,
    66856,
    66857
  );

  script_name(english:"Safari < 5.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Safari installed on the remote Windows host is earlier
than 5.0.1.  Such versions are potentially affected by numerous 
issues in the following components :

  - Safari

  - WebKit"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4276"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Jul/msg00001.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


path = get_kb_item("SMB/Safari/Path");
version = get_kb_item("SMB/Safari/FileVersion");
if (isnull(version)) exit(1, "The 'SMB/Safari/FileVersion' KB item is missing.");

version_ui = get_kb_item("SMB/Safari/ProductVersion");
if (isnull(version_ui)) version_ui = version;

if (ver_compare(ver:version, fix:"5.33.17.8") == -1)
{
  if (report_verbosity > 0)
  {
    if (isnull(path)) path = "n/a";

    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version_ui + 
      '\n  Fixed version     : 5.0.1\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The remote host is not affected since Safari " + version_ui + " is installed.");
