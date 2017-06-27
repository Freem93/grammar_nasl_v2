#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-491.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74700);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/17 10:38:58 $");

  script_cve_id("CVE-2012-3355");

  script_name(english:"openSUSE Security Update : rhythmbox (openSUSE-SU-2012:0954-1)");
  script_summary(english:"Check for the openSUSE-2012-491 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update fixes problems in rhythmbox :

  - Add rhythmbox-CVE-2012-3355.patch: fix insecure
    temporary directory use in context plugin. (bnc#768681,
    CVE-2012-3355)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768681"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhythmbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rhythmbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rhythmbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rhythmbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rhythmbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rhythmbox-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/27");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"rhythmbox-0.13.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rhythmbox-debuginfo-0.13.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rhythmbox-debugsource-0.13.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rhythmbox-devel-0.13.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"rhythmbox-lang-0.13.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rhythmbox-0.13.3-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rhythmbox-debuginfo-0.13.3-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rhythmbox-debugsource-0.13.3-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rhythmbox-devel-0.13.3-17.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rhythmbox-lang-0.13.3-17.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhythmbox / rhythmbox-debuginfo / rhythmbox-debugsource / etc");
}
