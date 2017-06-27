#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-647.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79222);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/13 14:27:26 $");

  script_cve_id("CVE-2014-3566");

  script_name(english:"openSUSE Security Update : libserf (openSUSE-SU-2014:1395-1) (POODLE)");
  script_summary(english:"Check for the openSUSE-2014-647 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libserf was updated to disable SSLv2 and SSLv3. &#9; libserf was
updated to version 1.3.8 on openSUSE 13.1 and 13.2. This release also
fixes a problem with handling very large gzip-encoded HTTP responses.

For openSUSE 12.3 libserf 1.1.1 was patched to disable SSLv2 and
SSLv3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00035.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libserf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libserf-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libserf-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libserf-1-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libserf-1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libserf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libserf-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libserf-1-0-1.1.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libserf-1-0-debuginfo-1.1.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libserf-debugsource-1.1.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libserf-devel-1.1.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libserf-1-1-1.3.8-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libserf-1-1-debuginfo-1.3.8-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libserf-debugsource-1.3.8-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libserf-devel-1.3.8-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libserf-1-1-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libserf-1-1-debuginfo-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libserf-debugsource-1.3.8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libserf-devel-1.3.8-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libserf");
}
