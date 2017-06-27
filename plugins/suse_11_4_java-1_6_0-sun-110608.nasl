#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-sun-4694.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75873);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id("CVE-2011-0786", "CVE-2011-0788", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0815", "CVE-2011-0817", "CVE-2011-0862", "CVE-2011-0863", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0866", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0872", "CVE-2011-0873");

  script_name(english:"openSUSE Security Update : java-1_6_0-sun (openSUSE-SU-2011:0633-1)");
  script_summary(english:"Check for the java-1_6_0-sun-4694 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Oracle Java 6 Update 26 fixes several security vulnerabilities.

Please refer to Oracle's site for further information:
http://www.oracle.com/technetwork/topics/security/javacpujun
e2011-313339.html

(CVE-2011-0862, CVE-2011-0873, CVE-2011-0815, CVE-2011-0817,
CVE-2011-0863, CVE-2011-0864, CVE-2011-0802, CVE-2011-0814,
CVE-2011-0871, CVE-2011-0786, CVE-2011-0788, CVE-2011-0866,
CVE-2011-0868, CVE-2011-0872, CVE-2011-0867, CVE-2011-0869,
CVE-2011-0865)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-06/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/topics/security/javacpujun"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698754"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/08");
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

if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-sun-1.6.0.u26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-sun-alsa-1.6.0.u26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-sun-demo-1.6.0.u26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-sun-devel-1.6.0.u26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-sun-jdbc-1.6.0.u26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-sun-plugin-1.6.0.u26-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-sun-src-1.6.0.u26-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-sun / java-1_6_0-sun-alsa / java-1_6_0-sun-demo / etc");
}
