#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update NetworkManager-5373.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75976);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2006-7246", "CVE-2011-2176");
  script_osvdb_id(73318, 77301);

  script_name(english:"openSUSE Security Update : NetworkManager (openSUSE-SU-2011:1273-1)");
  script_summary(english:"Check for the NetworkManager-5373 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NetworkManager did not pin a certificate's subject to an ESSID. A
rogue access point could therefore be used to conduct MITM attacks by
using any other valid certificate issued by same CA as used in the
original network (CVE-2006-7246).

Please note that existing WPA2 Enterprise connections need to be
deleted and re-created to take advantage of the new security checks.

NetworkManager did not honor the PolicyKit auth_admin setting when
creating Ad-Hoc wireless networks (CVE-2011-2176)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-11/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=574266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702016"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected NetworkManager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-glib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/04");
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

if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-0.8.2-15.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-debuginfo-0.8.2-15.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-debugsource-0.8.2-15.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-devel-0.8.2-15.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-glib-0.8.2-15.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-glib-debuginfo-0.8.2-15.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-gnome-0.8.2-9.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-gnome-debuginfo-0.8.2-9.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-gnome-debugsource-0.8.2-9.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-gnome-lang-0.8.2-9.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"NetworkManager-lang-0.8.2-15.28.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wpa_supplicant-0.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wpa_supplicant-debuginfo-0.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wpa_supplicant-debugsource-0.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wpa_supplicant-gui-0.7.3-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wpa_supplicant-gui-debuginfo-0.7.3-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-devel / NetworkManager-glib / etc");
}
