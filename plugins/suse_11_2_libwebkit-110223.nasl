#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libwebkit-4112.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53886);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/13 20:00:36 $");

  script_cve_id("CVE-2010-2441", "CVE-2010-2901", "CVE-2010-4042", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");

  script_name(english:"openSUSE Security Update : libwebkit (openSUSE-SU-2011:0482-1)");
  script_summary(english:"Check for the libwebkit-4112 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version upgrade of webkit to 1.2.7 fixes the following bugs :

  - CVE-2010-2441: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:P/I:N/A:N): Permissions, Privileges,
    and Access Control (CWE-264)

  - CVE-2010-2901: CVSS v2 Base Score: 3.7
    (AV:L/AC:H/Au:N/C:P/I:P/A:P): Buffer Errors (CWE-119)

  - CVE-2010-4042: CVSS v2 Base Score: 3.7
    (AV:L/AC:H/Au:N/C:P/I:P/A:P): Input Validation (CWE-20)

  - CVE-2010-4492: CVSS v2 Base Score: 7.5
    (AV:N/AC:L/Au:N/C:P/I:P/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-4493: CVSS v2 Base Score: 3.7
    (AV:L/AC:H/Au:N/C:P/I:P/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-4578: CVSS v2 Base Score: 3.7
    (AV:L/AC:H/Au:N/C:P/I:P/A:P): Input Validation (CWE-20)

  - CVE-2011-0482: CVSS v2 Base Score: 3.7
    (AV:L/AC:H/Au:N/C:P/I:P/A:P): Numeric Errors (CWE-189)

  - CVE-2011-0778: CVSS v2 Base Score: 3.7
    (AV:L/AC:H/Au:N/C:P/I:P/A:P): Permissions, Privileges,
    and Access Control (CWE-264)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-05/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617401"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwebkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-1_0-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"libwebkit-1_0-2-1.2.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libwebkit-devel-1.2.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libwebkit-lang-1.2.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"webkit-jsc-1.2.7-0.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkit");
}
