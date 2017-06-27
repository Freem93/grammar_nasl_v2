#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update imlib2-5804.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(35005);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:11:35 $");

  script_cve_id("CVE-2008-5187");

  script_name(english:"openSUSE 10 Security Update : imlib2 (imlib2-5804)");
  script_summary(english:"Check for the imlib2-5804 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security problem was fixed in imlib2 where loading a specific XPM
file could corrupt memory. (CVE-2008-5187)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imlib2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:imlib2-loaders");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"imlib2-1.2.1-48") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"imlib2-devel-1.2.1-48") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"imlib2-filters-1.2.1-48") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"imlib2-loaders-1.2.1-48") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"imlib2-1.3.0-66.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"imlib2-devel-1.3.0-66.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"imlib2-filters-1.3.0-66.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"imlib2-loaders-1.3.0-66.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imlib2");
}
