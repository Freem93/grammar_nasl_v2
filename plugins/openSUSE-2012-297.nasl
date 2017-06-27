#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-297.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74636);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2392", "CVE-2012-2393", "CVE-2012-2394");
  script_osvdb_id(82098, 82099, 82100, 82154, 82155, 82156, 82157, 82158, 82159, 82160);

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2012:0657-1)");
  script_summary(english:"Check for the openSUSE-2012-297 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update is a maintenance release of Wireshark. It fixes some
vulererabilities when dissecting certain protocols. As packages for
these protocols may be received over the network, an attacker may
trigger infinite or large loops or crashes of the dissector. Wireshark
release notes and advisories :

- http://www.wireshark.org/docs/relnotes/wireshark-1.4.13.html

- http://www.wireshark.org/security/wnpa-sec-2012-08.html

  - CVE-2012-2392

- http://www.wireshark.org/security/wnpa-sec-2012-09.html

  - CVE-2012-2393

- http://www.wireshark.org/security/wnpa-sec-2012-10.html

  - CVE-2012-2394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2012-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2012-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2012-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763634"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/25");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"wireshark-1.4.13-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wireshark-debuginfo-1.4.13-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wireshark-debugsource-1.4.13-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"wireshark-devel-1.4.13-0.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-1.4.13-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debuginfo-1.4.13-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debugsource-1.4.13-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-devel-1.4.13-3.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
