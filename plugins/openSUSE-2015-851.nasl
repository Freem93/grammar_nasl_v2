#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-851.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87389);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/16 15:10:33 $");

  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");

  script_name(english:"openSUSE Security Update : LibVNCServer (openSUSE-2015-851)");
  script_summary(english:"Check for the openSUSE-2015-851 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The LibVNCServer package was updated to fix the following security
issues :

  - bsc#897031: fix several security issues :

  - CVE-2014-6051: Integer overflow in MallocFrameBuffer()
    on client side.

  - CVE-2014-6052: Lack of malloc() return value checking on
    client side.

  - CVE-2014-6053: Server crash on a very large
    ClientCutText message.

  - CVE-2014-6054: Server crash when scaling factor is set
    to zero.

  - CVE-2014-6055: Multiple stack overflows in File Transfer
    feature.

  - bsc#854151: Restrict the SSL cipher suite."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=854151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897031"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected LibVNCServer packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:LibVNCServer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:LibVNCServer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncserver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncserver0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:linuxvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:linuxvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"LibVNCServer-debugsource-0.9.9-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"LibVNCServer-devel-0.9.9-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvncclient0-0.9.9-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvncclient0-debuginfo-0.9.9-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvncserver0-0.9.9-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libvncserver0-debuginfo-0.9.9-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"linuxvnc-0.9.9-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"linuxvnc-debuginfo-0.9.9-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibVNCServer-debugsource / LibVNCServer-devel / libvncclient0 / etc");
}
