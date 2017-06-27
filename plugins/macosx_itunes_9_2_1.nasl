#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47764);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2010-1777");
  script_bugtraq_id(41789);
  script_osvdb_id(66456);

  script_name(english:"iTunes < 9.2.1 'itpc:' Buffer Overflow (Mac OS X)");
  script_summary(english:"Checks version of iTunes on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of iTunes installed on the remote Mac OS X host is older
than 9.2.1.  Such versions may be affected by a buffer overflow
vulnerability in the handling of 'itpc:' URLs which may allow an
attacker to execute arbitrary code on the remote host. 

To exploit this vulnerability, an attacker would need to send a
malformed itpc: link to user on the remote host and wait for him to
click on it.");

  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4263"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to iTunes 9.2.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "9.2.1"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
