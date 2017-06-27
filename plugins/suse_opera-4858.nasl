#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update opera-4858.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(29884);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2007-6520", "CVE-2007-6521", "CVE-2007-6522", "CVE-2007-6523", "CVE-2007-6524");

  script_name(english:"openSUSE 10 Security Update : opera (opera-4858)");
  script_summary(english:"Check for the opera-4858 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Opera released version 9.25 of their browser to fix various security
problems.

CVE-2007-6520: Fixed an issue where plug-ins could be used to allow
cross domain scripting, as reported by David Bloom. Details will be
disclosed at a later date.

CVE-2007-6521: Fixed an issue with TLS certificates that could be used
to execute arbitrary code, as reported by Alexander Klink (Cynops
GmbH). Details will be disclosed at a later date.

CVE-2007-6522: Rich text editing can no longer be used to allow cross
domain scripting, as reported by David Bloom. See our advisory.

CVE-2007-6523: Fixed a problem where malformed BMP files could cause
Opera to temporarily freeze.

CVE-2007-6524: Prevented bitmaps from revealing random data from
memory, as reported by Gynvael Coldwind. Details will be disclosed at
a later date."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 189, 200, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"opera-9.25-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"opera-9.25-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"opera-9.25-1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
