#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-159.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88612);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2015-7576", "CVE-2015-7577", "CVE-2015-7581", "CVE-2016-0751", "CVE-2016-0752", "CVE-2016-0753");

  script_name(english:"openSUSE Security Update : rubygem-actionpack-4_2 / rubygem-actionview-4_2 / rubygem-activemodel-4_2 / etc (openSUSE-2016-159)");
  script_summary(english:"Check for the openSUSE-2016-159 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for rubygem-actionpack-4_2, rubygem-actionview-4_2,
rubygem-activemodel-4_2, rubygem-activerecord-4_2,
rubygem-activesupport-4_2 fixes the following issues :

  - CVE-2015-7576: Timing attack vulnerability in basic
    authentication in Action Controller (boo#963329)

  - CVE-2016-0752: directory traversal and information leak
    in Action View (boo#963332)

  - CVE-2015-7581: unbounded memory growth DoS via wildcard
    controller routes (boo#963335)

  - CVE-2016-0751: rubygem-actionpack: Object Leak DoS
    (boo#963331)

  - CVE-2016-0753: Input Validation Circumvention
    (boo#963334)

  - CVE-2015-7577: Nested attributes rejection proc bypass
    (boo#963330)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963335"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rubygem-actionpack-4_2 / rubygem-actionview-4_2 / rubygem-activemodel-4_2 / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails Dynamic Render File Upload Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-actionpack-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-actionpack-doc-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-actionview-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-actionview-doc-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-activemodel-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-activemodel-doc-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-activerecord-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-activerecord-doc-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-activesupport-4_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-rubygem-activesupport-doc-4_2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-actionpack-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-actionpack-doc-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-actionview-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-actionview-doc-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-activemodel-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-activemodel-doc-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-activerecord-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-activerecord-doc-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-activesupport-4_2-4.2.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-rubygem-activesupport-doc-4_2-4.2.4-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby2.1-rubygem-actionpack-4_2 / ruby2.1-rubygem-actionpack-doc-4_2 / etc");
}
