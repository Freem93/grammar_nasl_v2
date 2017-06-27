#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-415.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99153);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2016-10163", "CVE-2016-10214", "CVE-2017-5580", "CVE-2017-5937", "CVE-2017-5956", "CVE-2017-5957", "CVE-2017-5993", "CVE-2017-5994", "CVE-2017-6209", "CVE-2017-6210", "CVE-2017-6317", "CVE-2017-6355", "CVE-2017-6386");

  script_name(english:"openSUSE Security Update : virglrenderer (openSUSE-2017-415)");
  script_summary(english:"Check for the openSUSE-2017-415 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virglrenderer fixes the following issues :

Security issues fixed :

  - CVE-2017-6386: memory leakage while in
    vrend_create_vertex_elements_state (bsc#1027376)

  - CVE-2017-6355: integer overflow while creating shader
    object (bsc#1027108)

  - CVE-2017-6317: fix memory leak in add shader program
    (bsc#1026922)

  - CVE-2017-6210: NULL pointer dereference in
    vrend_decode_reset (bsc#1026725)

  - CVE-2017-6209: stack buffer oveflow in parse_identifier
    (bsc#1026723)

  - CVE-2017-5994: out-of-bounds access in
    vrend_create_vertex_elements_state (bsc#1025507)

  - CVE-2017-5993: host memory leakage when initialising
    blitter context (bsc#1025505)

  - CVE-2017-5957: stack overflow in
    vrend_decode_set_framebuffer_state (bsc#1024993)

  - CVE-2017-5956: OOB access while in vrend_draw_vbo
    (bsc#1024992)

  - CVE-2017-5937: NULL pointer dereference in vrend_clear
    (bsc#1024232)

  - CVE-2017-5580: OOB access while parsing texture
    instruction (bsc#1021627)

  - CVE-2016-10214: host memory leak issue in
    virgl_resource_attach_backing (bsc#1024244)

  - CVE-2016-10163: host memory leakage when creating decode
    context (bsc#1021616)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027376"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virglrenderer packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirglrenderer0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirglrenderer0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virglrenderer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virglrenderer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virglrenderer-test-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virglrenderer-test-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libvirglrenderer0-0.5.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libvirglrenderer0-debuginfo-0.5.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virglrenderer-debugsource-0.5.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virglrenderer-devel-0.5.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virglrenderer-test-server-0.5.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virglrenderer-test-server-debuginfo-0.5.0-3.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirglrenderer0 / libvirglrenderer0-debuginfo / etc");
}
