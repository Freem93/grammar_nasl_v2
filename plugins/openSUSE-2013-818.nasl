#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-818.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75185);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-4929");

  script_name(english:"openSUSE Security Update : openssl (openSUSE-SU-2013:1630-1)");
  script_summary(english:"Check for the openSUSE-2013-818 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update disables compression in openssl by default, as the varying
sizes resulting from compression can be used to retrieve plaintext in
various cases. (CRIME attack CVE-2012-4929).

This update introduces a environment variable OPENSSL_NO_DEFAULT_ZLIB
which can be set to 'no' to reenable compression in selected services."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793420"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/28");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libopenssl-devel-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libopenssl1_0_0-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libopenssl1_0_0-debuginfo-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"openssl-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"openssl-debuginfo-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"openssl-debugsource-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1e-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libopenssl-devel-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libopenssl1_0_0-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libopenssl1_0_0-debuginfo-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openssl-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openssl-debuginfo-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openssl-debugsource-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1e-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1e-1.13.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
