#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(59497);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2012-0672", "CVE-2012-0677");
  script_bugtraq_id(53404, 53933, 54113);
  script_osvdb_id(81792, 82897, 83220);
  script_xref(name:"EDB-ID", value:"19098");
  script_xref(name:"EDB-ID", value:"19322");
  script_xref(name:"EDB-ID", value:"19387");

  script_name(english:"Apple iTunes < 10.6.3 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a multimedia application that has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Windows host is
older than 10.6.3 and is, therefore, affected by the following issues :

  - A memory corruption issue exists in WebKit that can
    allow malicious websites to crash the application and
    possibly to execute arbitrary code. (CVE-2012-0672)

  - Stack and heap based buffer overflow errors related to
    the handling of 'm3u' playlist files. These errors can
    cause the application to crash or possibly allow
    arbitrary code execution. (CVE-2012-0677)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT5318"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00000.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iTunes 10 Extended M3U Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
fixed_version = "10.6.3.25";

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
else audit(AUDIT_INST_VER_NOT_VULN, "iTunes", version);
