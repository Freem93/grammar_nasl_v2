#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56871);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2008-3434");
  script_bugtraq_id(50672);
  script_osvdb_id(48328);

  script_name(english:"iTunes < 10.5.1 Update Authenticity Verification Weakness (Mac OS X)");
  script_summary(english:"Checks version of iTunes on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is susceptible to a
man-in-the-middle attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of iTunes installed on the remote Mac OS X host is
earlier than 10.5.1.  As such, it uses an unsecured HTTP connection
when checking for or retrieving software updates, which could allow a
man-in-the-middle attacker to provide a Trojan horse update that
appears to originate from Apple."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2008/Jul/249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.apple.com/kb/HT5030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Nov/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 10.5.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "10.5.1"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
