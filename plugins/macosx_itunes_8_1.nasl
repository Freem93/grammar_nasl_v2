#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35915);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2009-0143");
  script_bugtraq_id(34094);
  script_osvdb_id(52579);

  script_name(english:"iTunes < 8.1 Malicious Podcast Information Disclosure (Mac OS X)");
  script_summary(english:"Checks version of iTunes");

  script_set_attribute( attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
a remote information disclosure vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The remote version of iTunes is affected by a remote information
disclosure vulnerability.  By tricking a user on the affected host
into authenticating to a malicious podcast, an attacker could gain the
user's iTunes account information."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Mar/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 8.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/13");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/03/11");

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

constraints = [{"fixed_version" : "8.1"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
