#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-3.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80355);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/07 13:47:57 $");

  script_cve_id("CVE-2014-8131", "CVE-2014-8135", "CVE-2014-8136");

  script_name(english:"openSUSE Security Update : libvirt (openSUSE-SU-2015:0008-1)");
  script_summary(english:"Check for the openSUSE-2015-3 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2014-8135: libvirt: local denial of service in
    storage driver 87b9437f-CVE-2014-8135.patch bsc#910860

  - CVE-2014-8136: libvirt: local denial of service in qemu
    driver 2bdcd29c-CVE-2014-8136.patch bsc#910862

  - CVE-2014-8131: Fix possible deadlock and segfault in
    qemuConnectGetAllDomainStats()
    57023c0a-CVE-2014-8131.patch,
    cb104ef7-CVE-2014-8131.patch bsc#909274

  - Get /proc/sys/net/ipv[46] read-write for wicked to work
    in containers. bsc#904432. ba9b7252-sys-net-rw.patch

  - Fix potential crasher in virt-aa-helper
    2222123-virt-aa-helper-crash.patch

  - ip link add now needs the 'name' parameter.
    433b427-iplink-name.patch

  - Fixes for virt-sandbox-service to work :

  - Allow adding virt-sandbox service config to apparmor
    rules. c264eea-virt-aa-helper-sandbox.patch

  - fix symlink resolving for containers to start.
    72fecf1-lxc-resolve-symlinks.patch

  - fix unmounting file system if it contains the source to
    mount. e50457d-lxc-unmount-check.patch

  - Remove security_driver = 'none' in qemu config. This
    completely disabled all security drivers instead of
    probing them.

  - Changed default value of QEMU's
    security_default_confined to 0 to keep QEMU domains
    unconfined by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910862"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/05");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libvirt-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-client-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-client-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-config-network-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-config-nwfilter-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-interface-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-interface-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-lxc-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-lxc-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-network-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-network-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-nodedev-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-nodedev-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-nwfilter-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-nwfilter-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-qemu-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-qemu-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-secret-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-secret-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-storage-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-storage-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-uml-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-uml-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-vbox-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-driver-vbox-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-lxc-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-qemu-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-uml-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-daemon-vbox-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-debugsource-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-devel-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-lock-sanlock-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-lock-sanlock-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-login-shell-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvirt-login-shell-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-client-32bit-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-client-debuginfo-32bit-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-daemon-driver-xen-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-daemon-driver-xen-debuginfo-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-daemon-xen-1.2.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libvirt-devel-32bit-1.2.9-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-client-32bit / etc");
}
