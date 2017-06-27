#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update icedtea-web-4788.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75527);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2011-0815", "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0870", "CVE-2011-0871", "CVE-2011-0872");
  script_bugtraq_id(48137, 48139, 48140, 48141, 48142, 48143, 48144, 48146, 48147);

  script_name(english:"openSUSE Security Update : icedtea-web (openSUSE-SU-2011:0706-1)");
  script_summary(english:"Check for the icedtea-web-4788 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Icedtea as included in java-1_6_0-openjdk was updated to fix several
security issues :

  - S6213702, CVE-2011-0872: (so) non-blocking sockets with
    TCP urgent disabled get still selected for read ops
    (win)

  - S6618658, CVE-2011-0865: Vulnerability in
    deserialization

  - S7012520, CVE-2011-0815: Heap overflow vulnerability in
    FileDialog.show()

  - S7013519, CVE-2011-0822, CVE-2011-0862: Integer
    overflows in 2D code

  - S7013969, CVE-2011-0867: NetworkInterface.toString can
    reveal bindings

  - S7013971, CVE-2011-0869: Vulnerability in SAAJ

  - S7016340, CVE-2011-0870: Vulnerability in SAAJ

  - S7016495, CVE-2011-0868: Crash in Java 2D transforming
    an image with scale close to zero

  - S7020198, CVE-2011-0871: ImageIcon creates Component
    with null acc

  - S7020373, CVE-2011-0864: JSR rewriting can overflow
    memory address size"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-06/msg00044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=596177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698739"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/27");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"icedtea-web-1.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"icedtea-web-javadoc-1.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-openjdk-1.6.0.0_b22.1.10.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b22.1.10.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b22.1.10.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b22.1.10.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-openjdk-src-1.6.0.0_b22.1.10.2-4.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-javadoc / java-1_6_0-openjdk / etc");
}
