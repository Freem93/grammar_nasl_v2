#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49086);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id(
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
    "CVE-2010-1793"
  );
  script_bugtraq_id(
    42034,
    42035, 
    42036,
    42037,
    42038,
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

  script_name(english:"Apple iTunes < 10.0 Multiple (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Windows host is
older than 10.0. Such versions are affected by numerous issues in the
WebKit component.");
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4328"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Sep/msg00000.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
fixed_version = "10.0.0.68";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/iTunes/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since iTunes "+version+" is installed.");
