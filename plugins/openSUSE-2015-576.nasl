#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-576.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85926);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/14 13:50:03 $");

  script_cve_id("CVE-2015-5198", "CVE-2015-5199", "CVE-2015-5200");

  script_name(english:"openSUSE Security Update : libvdpau (openSUSE-2015-576)");
  script_summary(english:"Check for the openSUSE-2015-576 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libvdpau was updated to use secure_getenv() instead of getenv() for
several variables so it can be more safely used in setuid
applications.

  - CVE-2015-5198: libvdpau: incorrect check for security
    transition (bnc#943967)

  - CVE-2015-5199: libvdpau: directory traversal in dlopen
    (bnc#943968)

  - CVE-2015-5200: libvdpau: vulnerability in trace
    functionality (bnc#943969)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943969"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvdpau packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_trace1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_trace1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_trace1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_trace1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libvdpau-debugsource-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvdpau-devel-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvdpau1-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvdpau1-debuginfo-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvdpau_trace1-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvdpau_trace1-debuginfo-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvdpau-devel-32bit-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvdpau1-32bit-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvdpau1-debuginfo-32bit-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvdpau_trace1-32bit-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvdpau_trace1-debuginfo-32bit-0.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvdpau-debugsource-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvdpau-devel-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvdpau1-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvdpau1-debuginfo-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvdpau_trace1-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvdpau_trace1-debuginfo-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvdpau-devel-32bit-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvdpau1-32bit-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvdpau1-debuginfo-32bit-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvdpau_trace1-32bit-0.8-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvdpau_trace1-debuginfo-32bit-0.8-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvdpau-debugsource / libvdpau-devel / libvdpau-devel-32bit / etc");
}
