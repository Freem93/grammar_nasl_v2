#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29363);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");

  script_name(english:"SuSE 10 Security Update : MozillaFirefox (ZYPP Patch Number 4757)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to security update version 2.0.0.10

Following security problems were fixed: MFSA 2007-37 / CVE-2007-5947:
The jar protocol handler in Mozilla Firefox retrieves the inner URL
regardless of its MIME type, and considers HTML documents within a jar
archive to have the same origin as the inner URL, which allows remote
attackers to conduct cross-site scripting (XSS) attacks via a jar:
URI.

  - The Firefox 2.0.0.10 update contains fixes for three
    bugs that improve the stability of the product. These
    crashes showed some evidence of memory corruption under
    certain circumstances and we presume that with enough
    effort at least some of these could be exploited to run
    arbitrary code. (MFSA 2007-38 / CVE-2007-5959)

  - Gregory Fleischer demonstrated that it was possible to
    generate a fake HTTP Referer header by exploiting a
    timing condition when setting the window.location
    property. This could be used to conduct a Cross-site
    Request Forgery (CSRF) attack against websites that rely
    only on the Referer header as protection against such
    attacks. (MFSA 2007-39 / CVE-2007-5960)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2007/mfsa2007-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5947.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5959.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5960.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4757.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-2.0.0.10-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"MozillaFirefox-translations-2.0.0.10-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-2.0.0.10-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"MozillaFirefox-translations-2.0.0.10-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
