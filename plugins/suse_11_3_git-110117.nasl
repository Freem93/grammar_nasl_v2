#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update git-3832.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75516);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2010-2542", "CVE-2010-3906");

  script_name(english:"openSUSE Security Update : git (openSUSE-SU-2011:0115-1)");
  script_summary(english:"Check for the git-3832 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes two vulnerabilities :

XSS vulnerability in gitweb; a remote attacker could craft an URL such
that arbitrary content would be inserted to the generated web page.

Stack overflow vulnerability that can lead to arbitrary code
execution if user runs any git command on a specially
crafted git working copy.

Security Issue references :

-
[CVE-2010-3906](http://cve.mitre.org/cgi-bin/cvename.cgi?nam
e=CVE-2010-3906) 

-
[CVE-2010-2542](http://cve.mitre.org/cgi-bin/cvename.cgi?nam
e=CVE-2010-2542)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-02/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=659281"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-remote-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/17");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"git-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-arch-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-core-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-cvs-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-daemon-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-email-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-gui-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-remote-helpers-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-svn-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"git-web-1.7.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"gitk-1.7.1-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-arch / git-core / git-cvs / git-daemon / git-email / etc");
}
