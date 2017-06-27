#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-882.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87714);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/01/10 05:42:14 $");

  script_cve_id("CVE-2015-8045", "CVE-2015-8047", "CVE-2015-8048", "CVE-2015-8049", "CVE-2015-8050", "CVE-2015-8055", "CVE-2015-8056", "CVE-2015-8057", "CVE-2015-8058", "CVE-2015-8059", "CVE-2015-8060", "CVE-2015-8061", "CVE-2015-8062", "CVE-2015-8063", "CVE-2015-8064", "CVE-2015-8065", "CVE-2015-8066", "CVE-2015-8067", "CVE-2015-8068", "CVE-2015-8069", "CVE-2015-8070", "CVE-2015-8071", "CVE-2015-8401", "CVE-2015-8402", "CVE-2015-8403", "CVE-2015-8404", "CVE-2015-8405", "CVE-2015-8406", "CVE-2015-8407", "CVE-2015-8408", "CVE-2015-8409", "CVE-2015-8410", "CVE-2015-8411", "CVE-2015-8412", "CVE-2015-8413", "CVE-2015-8414", "CVE-2015-8415", "CVE-2015-8416", "CVE-2015-8417", "CVE-2015-8418", "CVE-2015-8419", "CVE-2015-8420", "CVE-2015-8421", "CVE-2015-8422", "CVE-2015-8423", "CVE-2015-8424", "CVE-2015-8425", "CVE-2015-8426", "CVE-2015-8427", "CVE-2015-8428", "CVE-2015-8429", "CVE-2015-8430", "CVE-2015-8431", "CVE-2015-8432", "CVE-2015-8433", "CVE-2015-8434", "CVE-2015-8435", "CVE-2015-8436", "CVE-2015-8437", "CVE-2015-8438", "CVE-2015-8439", "CVE-2015-8440", "CVE-2015-8441", "CVE-2015-8442", "CVE-2015-8443", "CVE-2015-8444", "CVE-2015-8445", "CVE-2015-8446", "CVE-2015-8447", "CVE-2015-8448", "CVE-2015-8449", "CVE-2015-8450", "CVE-2015-8451", "CVE-2015-8452", "CVE-2015-8453", "CVE-2015-8454", "CVE-2015-8455");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-2015-882)");
  script_summary(english:"Check for the openSUSE-2015-882 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flash-player to version 11.2.202.554 fixes the
following security issues in Adobe security advisory APSB15-32.

  - These updates resolve heap buffer overflow
    vulnerabilities that could lead to code execution
    (CVE-2015-8438, CVE-2015-8446).

  - These updates resolve memory corruption vulnerabilities
    that could lead to code execution (CVE-2015-8444,
    CVE-2015-8443, CVE-2015-8417, CVE-2015-8416,
    CVE-2015-8451, CVE-2015-8047, CVE-2015-8455,
    CVE-2015-8045, CVE-2015-8418, CVE-2015-8060,
    CVE-2015-8419, CVE-2015-8408).

  - These updates resolve security bypass vulnerabilities
    (CVE-2015-8453, CVE-2015-8440, CVE-2015-8409).

  - These updates resolve a stack overflow vulnerability
    that could lead to code execution (CVE-2015-8407).

  - These updates resolve a type confusion vulnerability
    that could lead to code execution (CVE-2015-8439).

  - These updates resolve an integer overflow vulnerability
    that could lead to code execution (CVE-2015-8445).

  - These updates resolve a buffer overflow vulnerability
    that could lead to code execution (CVE-2015-8415)

  - These updates resolve use-after-free vulnerabilities
    that could lead to code execution (CVE-2015-8050,
    CVE-2015-8049, CVE-2015-8437, CVE-2015-8450,
    CVE-2015-8449, CVE-2015-8448, CVE-2015-8436,
    CVE-2015-8452, CVE-2015-8048, CVE-2015-8413,
    CVE-2015-8412, CVE-2015-8410, CVE-2015-8411,
    CVE-2015-8424, CVE-2015-8422, CVE-2015-8420,
    CVE-2015-8421, CVE-2015-8423, CVE-2015-8425,
    CVE-2015-8433, CVE-2015-8432, CVE-2015-8431,
    CVE-2015-8426, CVE-2015-8430, CVE-2015-8427,
    CVE-2015-8428, CVE-2015-8429, CVE-2015-8434,
    CVE-2015-8435, CVE-2015-8414, CVE-2015-8454,
    CVE-2015-8059, CVE-2015-8058, CVE-2015-8055,
    CVE-2015-8057, CVE-2015-8056, CVE-2015-8061,
    CVE-2015-8067, CVE-2015-8066, CVE-2015-8062,
    CVE-2015-8068, CVE-2015-8064, CVE-2015-8065,
    CVE-2015-8063, CVE-2015-8405, CVE-2015-8404,
    CVE-2015-8402, CVE-2015-8403, CVE-2015-8071,
    CVE-2015-8401, CVE-2015-8406, CVE-2015-8069,
    CVE-2015-8070, CVE-2015-8441, CVE-2015-8442,
    CVE-2015-8447).

Please also see
&#9;https://helpx.adobe.com/security/products/flash-player/apsb15-32.h
tml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"flash-player-11.2.202.554-147.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-gnome-11.2.202.554-147.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-kde4-11.2.202.554-147.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-11.2.202.554-2.82.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-gnome-11.2.202.554-2.82.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-kde4-11.2.202.554-2.82.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player / flash-player-gnome / flash-player-kde4");
}
