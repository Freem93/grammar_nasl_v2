#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-78.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74812);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:26 $");

  script_cve_id("CVE-2011-4600");

  script_name(english:"openSUSE Security Update : libvirt (openSUSE-2012-78)");
  script_summary(english:"Check for the openSUSE-2012-78 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix authorization workflow with PolicyKit. polkit.patch
    bnc#735403

  - Fix qemu default migration speed. It should not be
    33554432Mb! 61f2b6ba-no-unlimited-mig2file-speed.patch
    d8916dc8-def-qemu-migspeed.patch

  - CVE-2011-4600: unintended firewall port exposure after
    restarting libvirtd when defining a bridged forward-mode
    network ae1232b2-CVE-2011-4600.patch bnc#736082

  - Fix default console type setting
    209c2880-multiple-consoles-7.patch

  - Fix 'virsh console' with Xen HVM
    xen-hvm-virsh-console.patch bnc#731974

  - Prevent libvirtd crash on 'virsh qemu-attach' when
    security_driver is 'none' in /etc/libvirt/qemu.conf
    28423019-qemu-attach-crash.patch bnc#735023

  - Allow qemu driver (and hence libvirtd) to load when qemu
    user:group does not exist. The kvm or qemu package,
    which may not exist on a xen host, creates qemu
    user:group. relax-qemu-usergroup-check.patch bnc#711096

  - Accommodate Xen domctl version 8 xen-domctl-ver8.patch

  - Handle empty strings in s-expression returned by xend
    a495365d-sexpr-empty-str.patch bnc#731344

  - Allow libvirtd to access libvirt_{io,part}helper when
    confined by apparmor Update
    install-apparmor-profiles.patch bnc#730435

  - Fixed to return success when there are no errors while
    parsing bonding interface miimon xml node parameters.
    bonding-miimon-xml-parsing.patch"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libvirt-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvirt-client-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvirt-client-debuginfo-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvirt-debuginfo-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvirt-debugsource-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvirt-devel-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvirt-python-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libvirt-python-debuginfo-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libvirt-client-32bit-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libvirt-client-debuginfo-32bit-0.9.6-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libvirt-devel-32bit-0.9.6-3.3.1") ) flag++;

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
