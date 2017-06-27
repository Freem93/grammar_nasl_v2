#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-74.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75162);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-0221", "CVE-2013-0222", "CVE-2013-0223");

  script_name(english:"openSUSE Security Update : coreutils (openSUSE-SU-2013:0233-1)");
  script_summary(english:"Check for the openSUSE-2013-74 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Avoid segmentation fault in 'join -i' with long line
    input (bnc#798541, VUL-1, CVE-2013-0223)

  - Avoid segmentation fault in 'uniq' with long line input
    (bnc#796243, VUL-1, CVE-2013-0222)

  - Avoid segmentation fault in 'sort -d' and 'sort -M' with
    long line input (bnc#798538, VUL-1, CVE-2013-0221)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798541"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected coreutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils-lang");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"coreutils-8.16-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"coreutils-debuginfo-8.16-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"coreutils-debugsource-8.16-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"coreutils-lang-8.16-5.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "coreutils / coreutils-debuginfo / coreutils-debugsource / etc");
}
