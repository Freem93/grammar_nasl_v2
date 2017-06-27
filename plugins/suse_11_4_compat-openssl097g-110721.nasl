#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update compat-openssl097g-4909.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75802);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2008-5077", "CVE-2009-0590", "CVE-2009-0789", "CVE-2009-3555", "CVE-2010-4180");

  script_name(english:"openSUSE Security Update : compat-openssl097g (openSUSE-SU-2011:0845-1)");
  script_summary(english:"Check for the compat-openssl097g-4909 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update adds openssl patches since 2007 for :

  - CVE-2008-5077

  - CVE-2009-0590

  - CVE-2009-0789

  - CVE-2009-3555

  - CVE-2010-4180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-07/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707069"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected compat-openssl097g packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(20, 119, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compat-openssl097g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compat-openssl097g-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compat-openssl097g-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compat-openssl097g-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:compat-openssl097g-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"compat-openssl097g-0.9.7g-158.159.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"compat-openssl097g-debuginfo-0.9.7g-158.159.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"compat-openssl097g-debugsource-0.9.7g-158.159.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"compat-openssl097g-32bit-0.9.7g-158.159.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"compat-openssl097g-debuginfo-32bit-0.9.7g-158.159.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openssl097g");
}
