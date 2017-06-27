#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libneon-devel-1377.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42315);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-2408", "CVE-2009-2473");

  script_name(english:"openSUSE Security Update : libneon-devel (libneon-devel-1377)");
  script_summary(english:"Check for the libneon-devel-1377 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"neon did not properly handle embedded NUL characters in X.509
certificates when comparing host names. Attackers could exploit that
to spoof SSL servers (CVE-2009-2408).

Specially crafted XML documents that contain a large number of nested
entity references could cause neon to consume large amounts of CPU and
memory (CVE-2009-2473)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=528370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=532345"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libneon-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libneon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libneon27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libneon27-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"libneon-devel-0.28.2-17.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libneon27-0.28.2-17.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"neon-0.28.2-17.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libneon27-32bit-0.28.2-17.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libneon-devel / libneon27 / libneon27-32bit / neon");
}
