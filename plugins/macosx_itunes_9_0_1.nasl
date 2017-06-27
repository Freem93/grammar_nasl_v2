#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41059);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2009-2817");
  script_bugtraq_id(36478);
  script_osvdb_id(58271);

  script_name(english:"iTunes < 9.0.1 PLS File Buffer Overflow (Mac OS X)");
  script_summary(english:"Checks version of iTunes");

  script_set_attribute( attribute:"synopsis", value:
"The remote Mac OS X host contains an application affected by a buffer
overflow vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The remote version of iTunes is older than 9.0.1. Such versions are
affected by a buffer overflow involving the handling of PLS files.  If
an attacker can trick a user on the affected host into opening a
malicious PLS file, he can leverage this issue to crash the affected
application or to execute arbitrary code on the affected system
subject to the user's privileges."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17952"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 9.0.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "9.0.1"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
