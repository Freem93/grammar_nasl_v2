#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53488);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/08/03 13:57:40 $");

  script_cve_id("CVE-2011-1290", "CVE-2011-1344");
  script_bugtraq_id(46849, 46822);
  script_osvdb_id(71182, 72690);

  script_name(english:"Apple iTunes < 10.2.2 Multiple (credentialed check)");
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
older than 10.2.2.  As such, it is potentially affected by several
issues :

  - An integer overflow issue in the handling of nodesets
    could lead to a crash or arbitrary code execution.
    (CVE-2011-1290)

  - A use after free issue in the handling of text nodes
    could lead to a crash or arbitrary code execution.
    (CVE-2011-1344)");

  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4609");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Apr/msg00004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
fixed_version = "10.2.2.12";

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
