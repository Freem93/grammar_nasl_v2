#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-503.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99617);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/25 13:34:11 $");

  script_cve_id("CVE-2017-7700", "CVE-2017-7701", "CVE-2017-7702", "CVE-2017-7703", "CVE-2017-7704", "CVE-2017-7705", "CVE-2017-7745", "CVE-2017-7746", "CVE-2017-7747", "CVE-2017-7748");
  script_xref(name:"IAVB", value:"2017-B-0046");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2017-503)");
  script_summary(english:"Check for the openSUSE-2017-503 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Wireshark 2.2.6 fixes minor vulnerabilities that could
be used to trigger a dissector crash or infinite loops by sending
specially crafted packages over the network or into a capture file :

  - CVE-2017-7700: NetScaler file parser infinite loop
    (boo#1033936)

  - CVE-2017-7701: BGP dissector infinite loop (boo#1033937)

  - CVE-2017-7702: WBMXL dissector infinite loop
    (boo#1033938)

  - CVE-2017-7703: IMAP dissector crash (boo#1033939)

  - CVE-2017-7704: DOF dissector infinite loop (boo#1033940)

  - CVE-2017-7705: RPCoRDMA dissector infinite loop
    (boo#1033941)

  - CVE-2017-7745: SIGCOMP dissector infinite loop
    (boo#1033942)

  - CVE-2017-7746: SLSK dissector long loop (boo#1033943)

  - CVE-2017-7747: PacketBB dissector crash (boo#1033944)

  - CVE-2017-7748: WSP dissector infinite loop (boo#1033945)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033945"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"wireshark-2.2.6-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-debuginfo-2.2.6-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-debugsource-2.2.6-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-devel-2.2.6-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-gtk-2.2.6-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-gtk-debuginfo-2.2.6-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-qt-2.2.6-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-qt-debuginfo-2.2.6-14.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
