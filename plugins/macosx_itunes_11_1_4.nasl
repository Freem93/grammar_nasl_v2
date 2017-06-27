#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72106);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2014-1242");
  script_bugtraq_id(65088);
  script_osvdb_id(102410);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-01-22-1");

  script_name(english:"iTunes < 11.1.4 Tutorials Content Injection (Mac OS X)");
  script_summary(english:"Checks version of iTunes on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a multimedia application that has a content
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of iTunes installed on the remote Mac OS X host is a
version prior to 11.1.4.  It is, therefore, affected by an error related
to the iTunes Tutorials window that could allow an attacker in a
privileged network location to inject content."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to iTunes 11.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6001");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530870/30/0/threaded");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "11.1.4"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
