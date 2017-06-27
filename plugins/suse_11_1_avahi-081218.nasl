#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update avahi-384.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40192);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/13 15:30:41 $");

  script_cve_id("CVE-2008-5081");

  script_name(english:"openSUSE Security Update : avahi (avahi-384)");
  script_summary(english:"Check for the avahi-384 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted mDNS packets could crash the Avahi daemon
(CVE-2008-5081)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=459007"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected avahi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-compat-mDNSResponder-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-client3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-common3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-ui0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns_sd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhowl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"avahi-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"avahi-compat-howl-devel-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"avahi-compat-mDNSResponder-devel-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"avahi-utils-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-client3-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-common3-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-core5-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-devel-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-glib-devel-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-glib1-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-gobject-devel-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-gobject0-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libavahi-ui0-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libdns_sd-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libhowl0-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"python-avahi-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libavahi-client3-32bit-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libavahi-common3-32bit-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libavahi-glib1-32bit-0.6.23-9.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libdns_sd-32bit-0.6.23-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-compat-howl-devel / avahi-compat-mDNSResponder-devel / etc");
}
