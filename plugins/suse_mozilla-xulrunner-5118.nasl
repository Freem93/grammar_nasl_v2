#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31696);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");

  script_name(english:"SuSE 10 Security Update : epiphany (ZYPP Patch Number 5118)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the Mozilla XULRunner engine catches up on all previous
security problems found in the XULRunner engine.

Following security problems were fixed :

  - Web forgery overwrite with div overlay. (MFSA 2008-11 /
    CVE-2008-0594)

  - URL token stealing via stylesheet redirect. (MFSA
    2008-10 / CVE-2008-0593)

  - Mishandling of locally-saved plain text files. (MFSA
    2008-09 / CVE-2008-0592)

  - File action dialog tampering. (MFSA 2008-08 /
    CVE-2008-0591)

  - Web browsing history and forward navigation stealing.
    (MFSA 2008-06 / CVE-2008-0419)

  - Directory traversal via chrome: URI. (MFSA 2008-05 /
    CVE-2008-0418)

  - Stored password corruption. (MFSA 2008-04 /
    CVE-2008-0417)

  - Privilege escalation, XSS, Remote Code Execution. (MFSA
    2008-03 / CVE-2008-0415)

  - Multiple file input focus stealing vulnerabilities.
    (MFSA 2008-02 / CVE-2008-0414)

  - Crashes with evidence of memory corruption
    (rv:1.8.1.12). (MFSA 2008-01 / CVE-2008-0412)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-06.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0414.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0592.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0594.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5118.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 22, 79, 94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"epiphany-1.8.5-14.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"epiphany-devel-1.8.5-14.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"epiphany-doc-1.8.5-14.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"gecko-sdk-1.8.0.14eol-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"mozilla-xulrunner-1.8.0.14eol-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mozilla-xulrunner-1.8.0.14eol-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
