#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update opera-2991.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(48430);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/13 19:55:05 $");

  script_cve_id("CVE-2010-2576", "CVE-2010-3019", "CVE-2010-3020", "CVE-2010-3021");

  script_name(english:"openSUSE Security Update : opera (openSUSE-SU-2010:0540-1)");
  script_summary(english:"Check for the opera-2991 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of opera fixes the following vulnerabilities :

  - CVE-2010-2576: CVSS v2 Base Score: 6.8 (CWE-94):
    unexpected changes in tab focus could be used to run
    programs from the Internet, as reported by Jakob Balle
    and Sven Krewitt of Secunia

  - CVE-2010-3019: CVSS v2 Base Score: 9.3 (CWE-119): heap
    buffer overflow in HTML5 canvas could be used to execute
    arbitrary code, as reported by Kuzzcc

  - CVE-2010-3020: CVSS v2 Base Score: 5.0 (CWE-264): news
    feed preview could subscribe to feeds without
    interaction, as reported by Alexios Fakos

  - CVE-2010-3021: CVSS v2 Base Score: 4.3 (CWE-399): remote
    attackers could trigger a remote denial of service (CPU
    consumption and application hang) via an animated PNG
    image"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-08/msg00055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=630771"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"opera-10.61-0.1.1") ) flag++;

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
