#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25999);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2007-3752");
  script_bugtraq_id(25567);
  script_osvdb_id(38528);

  script_name(english:"iTunes < 7.4 Malformed Music File Heap Overflow (Mac OS X)");
  script_summary(english:"Check the version of iTunes");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by a
remote code execution flaw." );
  script_set_attribute(attribute:"description", value:
"The remote host is running iTunes, a popular jukebox program. 

The remote version of iTunes is vulnerable to a heap overflow when it
parses a specially crafted MP4/AAC file.  By tricking a user into
opening such a file, a remote attacker may be able to leverage this
issue to execute arbitrary code on the affected host, subject to the
privileges of the user running the application." );
  # http://web.archive.org/web/20070911122710/http://docs.info.apple.com/article.html?artnum=306404
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8e1b4d0" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 7.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/07");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/06");
  script_set_attribute(attribute:"patch_publication_date", value: "2007/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "7.4"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
