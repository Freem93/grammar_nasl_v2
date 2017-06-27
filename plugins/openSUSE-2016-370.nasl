#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-370.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90062);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:29 $");

  script_cve_id("CVE-2016-2510");

  script_name(english:"openSUSE Security Update : bsh2 (openSUSE-2016-370)");
  script_summary(english:"Check for the openSUSE-2016-370 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bsh2 fixes the following issues :

  - Version update to 2.0b6 boo#967593 CVE-2016-2510

  - Upstream developement moved to github

  - No obvious changelog apart from the above"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967593"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bsh2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsh2-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsh2-classgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsh2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsh2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsh2-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"bsh2-2.0.0.b6-27.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bsh2-bsf-2.0.0.b6-27.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bsh2-classgen-2.0.0.b6-27.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bsh2-demo-2.0.0.b6-27.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bsh2-javadoc-2.0.0.b6-27.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bsh2-manual-2.0.0.b6-27.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsh2 / bsh2-bsf / bsh2-classgen / bsh2-demo / bsh2-javadoc / etc");
}
