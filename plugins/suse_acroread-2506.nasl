#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update acroread-2506.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27144);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/22 20:32:44 $");

  script_cve_id("CVE-2006-5857", "CVE-2007-0044", "CVE-2007-0045", "CVE-2007-0046", "CVE-2007-0047", "CVE-2007-0048");

  script_name(english:"openSUSE 10 Security Update : acroread (acroread-2506)");
  script_summary(english:"Check for the acroread-2506 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Adobe Acrobat Reader has been updated to version 7.0.9.

This update also includes following security fixes :

CVE-2006-5857: A memory corruption problem was fixed in Adobe Acrobat
Reader can potentially lead to code execution.

CVE-2007-0044: Universal Cross Site Request Forgery (CSRF) problems
were fixed in the Acrobat Reader plugin which could be exploited by
remote attackers to conduct CSRF attacks using any site that is
providing PDFs.

CVE-2007-0045: Cross site scripting problems in the Acrobat Reader
plugin were fixed, which could be exploited by remote attackers to
conduct XSS attacks against any site that is providing PDFs.

CVE-2007-0046: A double free problem in the Acrobat Reader plugin was
fixed which could be used by remote attackers to potentially execute
arbitrary code. Note that all platforms using Adobe Reader currently
have counter measures against such attack where it will just cause a
controlled abort().

CVE-2007-0047 and CVE-2007-0048 affect only Microsoft Windows and
Internet Explorer."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acroread package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(352, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"acroread-7.0.9-1.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"acroread-7.0.9-2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread");
}
