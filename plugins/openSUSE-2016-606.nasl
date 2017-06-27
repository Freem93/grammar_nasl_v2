#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-606.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91276);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2015-8618", "CVE-2016-3959");

  script_name(english:"openSUSE Security Update : go (openSUSE-2016-606)");
  script_summary(english:"Check for the openSUSE-2016-606 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This go update to version 1.6 fixes the following issues :

Security issues fixed :

  - CVE-2016-3959: Infinite loop in several big integer
    routines (boo#974232)

  - CVE-2015-8618: Carry propagation in Int.Exp Montgomery
    code in math/big library (boo#960151)

Bugs fixed :

  - Update to version 1.6 :

  - On Linux on little-endian 64-bit PowerPC
    (linux/ppc64le), Go 1.6 now supports cgo with external
    linking and is roughly feature complete.

  - Vendoring support

  - HTTP2 transparent support

  - fix gc and gccgo incompatibility regarding embedded
    unexported struct types containing exported fields

  - Linux on 64-bit MIPS and Android on 32-bit x86

  - enforced rules for sharing Go pointers with C

  - new mechanism for template reuse

  - performance improvements ... and more! see more in
    https://tip.golang.org/doc/go1.6 

  - Updated to version 1.5.2: This release includes bug
    fixes to the compiler, linker, and the mime/multipart,
    net, and runtime packages.
    https://golang.org/doc/devel/release.html#go1.5.minor

  - Updated to version 1.5.1: &#9;This release includes bug
    fixes to the go command, the compiler, assembler, and
    the fmt, net/textproto, net/http, and runtime packages.
    https://golang.org/doc/devel/release.html#go1.5.minor

  - Update to version 1.5 :

  - see https://golang.org/doc/go1.5 

  - install shared stdlib on x86_64

  - add go.gdbinit for debug friendly

  - Adapt to Leap

  - use gcc5-go than go1.4 is the proper requirement for
    Leap"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://golang.org/doc/devel/release.html#go1.5.minor"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://golang.org/doc/go1.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://tip.golang.org/doc/go1.6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected go packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"go-1.6.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"go-debuginfo-1.6.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"go-debugsource-1.6.1-14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go / go-debuginfo / go-debugsource");
}
