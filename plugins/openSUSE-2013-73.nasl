#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-73.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75160);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-0420");
  script_osvdb_id(89249);

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-SU-2013:0231-1)");
  script_summary(english:"Check for the openSUSE-2013-73 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - added CVE-2013-0420.diff to fix CVE-2013-0420
    (bnc#798776)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798776"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"python-virtualbox-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-virtualbox-debuginfo-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-debuginfo-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-debugsource-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-devel-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-default-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-desktop-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-pae-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-tools-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-tools-debuginfo-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-x11-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-guest-x11-debuginfo-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-default-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-default-debuginfo-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-desktop-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-pae-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.1.22_k3.1.10_1.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-qt-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"virtualbox-qt-debuginfo-4.1.22-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-virtualbox-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-virtualbox-debuginfo-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-debuginfo-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-debugsource-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-devel-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-default-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-default-debuginfo-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-desktop-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-pae-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-kmp-pae-debuginfo-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-tools-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-tools-debuginfo-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-x11-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-guest-x11-debuginfo-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-default-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-default-debuginfo-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-desktop-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-desktop-debuginfo-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-pae-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-host-kmp-pae-debuginfo-4.1.22_k3.4.11_2.16-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-qt-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-qt-debuginfo-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-websrv-4.1.22-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"virtualbox-websrv-debuginfo-4.1.22-1.10.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtualbox / python-virtualbox-debuginfo / virtualbox / etc");
}
