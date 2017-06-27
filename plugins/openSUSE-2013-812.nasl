#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-812.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75183);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4288", "CVE-2013-4325");
  script_osvdb_id(97509, 97511);

  script_name(english:"openSUSE Security Update : hplip (openSUSE-SU-2013:1617-1)");
  script_summary(english:"Check for the openSUSE-2013-812 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"the following security issue was fixed for HPLIP 3.13.10: usage of an
insecure polkit DBUS API (fix for bnc#836937 and CVE-2013-4325 that
are related to CVE-2013-4288 and bnc#835827)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836937"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hplip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hplip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hplip-hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hplip-hpijs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hplip-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hplip-sane-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"hplip-3.12.4-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"hplip-debuginfo-3.12.4-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"hplip-debugsource-3.12.4-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"hplip-hpijs-3.12.4-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"hplip-hpijs-debuginfo-3.12.4-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"hplip-sane-3.12.4-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"hplip-sane-debuginfo-3.12.4-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"hplip-3.12.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"hplip-debuginfo-3.12.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"hplip-debugsource-3.12.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"hplip-hpijs-3.12.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"hplip-hpijs-debuginfo-3.12.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"hplip-sane-3.12.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"hplip-sane-debuginfo-3.12.11-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hplip / hplip-debuginfo / hplip-debugsource / hplip-hpijs / etc");
}
