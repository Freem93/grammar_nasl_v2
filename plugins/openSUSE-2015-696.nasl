#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-696.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86731);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/05 16:11:32 $");

  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4810", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4868", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4901", "CVE-2015-4902", "CVE-2015-4903", "CVE-2015-4906", "CVE-2015-4908", "CVE-2015-4911", "CVE-2015-4916");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2015-696)");
  script_summary(english:"Check for the openSUSE-2015-696 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_8_0-openjdk was updated to fix 24 security issues.

These security issues were fixed :

  - CVE-2015-4734: A remote user can exploit a flaw in the
    Embedded JGSS component to partially access data

  - CVE-2015-4803: A remote user can exploit a flaw in the
    JRockit JAXP component to cause partial denial of
    service conditions

  - CVE-2015-4805: A remote user can exploit a flaw in the
    Embedded Serialization component to gain elevated
    privileges

  - CVE-2015-4806: A remote user can exploit a flaw in the
    Java SE Embedded Libraries component to partially access
    and partially modify data

  - CVE-2015-4835: A remote user can exploit a flaw in the
    Embedded CORBA component to gain elevated privileges

  - CVE-2015-4842: A remote user can exploit a flaw in the
    Embedded JAXP component to partially access data

  - CVE-2015-4843: A remote user can exploit a flaw in the
    Java SE Embedded Libraries component to gain elevated
    privileges

  - CVE-2015-4844: A remote user can exploit a flaw in the
    Embedded 2D component to gain elevated privileges

  - CVE-2015-4860: A remote user can exploit a flaw in the
    Embedded RMI component to gain elevated privileges

  - CVE-2015-4872: A remote user can exploit a flaw in the
    JRockit Security component to partially modify data [].

  - CVE-2015-4881: A remote user can exploit a flaw in the
    Embedded CORBA component to gain elevated privileges

  - CVE-2015-4882: A remote user can exploit a flaw in the
    Embedded CORBA component to cause partial denial of
    service conditions

  - CVE-2015-4883: A remote user can exploit a flaw in the
    Embedded RMI component to gain elevated privileges

  - CVE-2015-4893: A remote user can exploit a flaw in the
    JRockit JAXP component to cause partial denial of
    service conditions

  - CVE-2015-4902: A remote user can exploit a flaw in the
    Java SE Deployment component to partially modify data

  - CVE-2015-4903: A remote user can exploit a flaw in the
    Embedded RMI component to partially access data

  - CVE-2015-4911: A remote user can exploit a flaw in the
    JRockit JAXP component to cause partial denial of
    service conditions

  - CVE-2015-4810: A local user can exploit a flaw in the
    Java SE Deployment component to gain elevated privileges

  - CVE-2015-4840: A remote user can exploit a flaw in the
    Embedded 2D component to partially access data

  - CVE-2015-4868: A remote user can exploit a flaw in the
    Java SE Embedded Libraries component to gain elevated
    privileges

  - CVE-2015-4901: A remote user can exploit a flaw in the
    JavaFX component to gain elevated privileges

  - CVE-2015-4906: A remote user can exploit a flaw in the
    JavaFX component to partially access data

  - CVE-2015-4908: A remote user can exploit a flaw in the
    JavaFX component to partially access data

  - CVE-2015-4916: A remote user can exploit a flaw in the
    JavaFX component to partially access data"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951376"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-demo-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-devel-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-headless-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.65-18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-src-1.8.0.65-18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
