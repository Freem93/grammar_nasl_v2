#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59499);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2012-0677");
  script_bugtraq_id(53933, 54113);
  script_osvdb_id(81792, 82897, 83220);
  script_xref(name:"EDB-ID", value:"19098");
  script_xref(name:"EDB-ID", value:"19322");
  script_xref(name:"EDB-ID", value:"19387");

  script_name(english:"iTunes < 10.6.3 m3u Multiple Buffer Overflow Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of iTunes on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a multimedia application that has multiple
buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of iTunes installed on the remote Mac OS X host is
earlier than 10.6.3 and is, therefore, affected by stack and heap
based buffer overflow vulnerabilities. The application does not
properly handle 'm3u' playlist files. This error can cause the
application to crash or possibly allow arbitrary code execution."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 10.6.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iTunes 10 Extended M3U Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT5318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00000.html"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "10.6.3"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
