#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-328.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75338);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-6456", "CVE-2013-7336");

  script_name(english:"openSUSE Security Update : libvirt (openSUSE-SU-2014:0593-1)");
  script_summary(english:"Check for the openSUSE-2014-328 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libvirt was updated to fix various bugs and security issues :

CVE-2013-7336: libvirt: unprivileged user can crash libvirtd during
spice migration

CVE-2013-6456: unsafe usage of paths under /proc/$PID/root

Bugfixes for libvirt client killed on reboot shutdown. (bnc#852005)

Also notify systemd when we are ready to accept connections."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=873103"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:P/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-uml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-uml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-vbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-uml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-login-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libvirt-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-client-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-client-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-config-network-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-config-nwfilter-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-interface-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-interface-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-lxc-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-lxc-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-network-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-network-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-nodedev-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-nodedev-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-nwfilter-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-nwfilter-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-qemu-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-qemu-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-secret-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-secret-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-storage-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-storage-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-uml-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-uml-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-vbox-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-driver-vbox-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-lxc-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-qemu-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-uml-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-daemon-vbox-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-debugsource-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-devel-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-lock-sanlock-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-lock-sanlock-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-login-shell-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-login-shell-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-python-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libvirt-python-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-client-32bit-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-client-debuginfo-32bit-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-daemon-driver-xen-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-daemon-driver-xen-debuginfo-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-daemon-xen-1.1.2-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libvirt-devel-32bit-1.1.2-2.26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
