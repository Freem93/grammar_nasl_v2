#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-391.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75371);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_bugtraq_id(67382);

  script_name(english:"openSUSE Security Update : libXfont (openSUSE-SU-2014:0711-1)");
  script_summary(english:"Check for the openSUSE-2014-391 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libxfont was updated to fix multiple vulnerabilities :

  - Integer overflow of allocations in font metadata file
    parsing (CVE-2014-0209).

  - Unvalidated length fields when parsing xfs protocol
    replies (CVE-2014-0210).

  - Integer overflows calculating memory needs for xfs
    replies (CVE-2014-0211).

These vulnerabilities could be used by a local, authenticated user to
raise privileges or by a remote attacker with control of the font
server to execute code with the privileges of the X server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857544"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXfont packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/16");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libXfont-debugsource-1.4.5-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXfont-devel-1.4.5-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXfont1-1.4.5-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXfont1-debuginfo-1.4.5-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXfont-devel-32bit-1.4.5-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXfont1-32bit-1.4.5-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.4.5-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont-debugsource-1.4.6-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont-devel-1.4.6-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-1.4.6-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-debuginfo-1.4.6-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont-devel-32bit-1.4.6-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-32bit-1.4.6-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.4.6-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont");
}
