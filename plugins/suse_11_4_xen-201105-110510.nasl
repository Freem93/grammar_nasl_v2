#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xen-201105-4534.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76048);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:19:38 $");

  script_cve_id("CVE-2011-1146", "CVE-2011-1166", "CVE-2011-1486", "CVE-2011-1583");

  script_name(english:"openSUSE Security Update : xen-201105 (openSUSE-SU-2011:0578-1)");
  script_summary(english:"Check for the xen-201105-4534 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Collective May/2011 update for Xen

Xen :

  - 675363 - Random lockups with kernel-xen. Possibly
    graphics related.

  - 679344 - Xen: multi-vCPU pv guest may crash host

  - 681044 - update xenpaging.autostart.patch

  - 681302 - xm create -x <guest> returns 'ImportError: No
    module named ext'

  - 688473 - potential buffer overflow in tools

  - 691738 - Xen does not find device create with npiv block

vm-install :

  - 688757 - SLED10SP4 fully virtualized in SLES10SP4 XEN -
    kernel panic

  - 678152 - Xen: virt-manager: harmless block device admin
    actions on FV guests mess up network (VIF) device type
    ==> network lost.

  - 631680 - OpenSUSE 11.3 KVM install of windows xp fails
    on first reboot during installation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-05/msg00065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=691238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=691738"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen-201105 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vm-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"vm-install-0.4.30-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-debugsource-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-devel-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-doc-html-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-doc-pdf-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-default-4.0.2_02_k2.6.37.6_0.5-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-default-debuginfo-4.0.2_02_k2.6.37.6_0.5-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-desktop-4.0.2_02_k2.6.37.6_0.5-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-desktop-debuginfo-4.0.2_02_k2.6.37.6_0.5-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-pae-4.0.2_02_k2.6.37.6_0.5-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-kmp-pae-debuginfo-4.0.2_02_k2.6.37.6_0.5-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-libs-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-libs-debuginfo-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-debuginfo-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-domU-4.0.2_02-4.9.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"xen-tools-domU-debuginfo-4.0.2_02-4.9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
