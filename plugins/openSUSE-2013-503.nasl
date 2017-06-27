#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-503.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75039);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1984", "CVE-2013-1995", "CVE-2013-1998");
  script_bugtraq_id(60123, 60124, 60127);
  script_osvdb_id(93660, 93663, 93675);

  script_name(english:"openSUSE Security Update : libXi (openSUSE-SU-2013:1033-1)");
  script_summary(english:"Check for the openSUSE-2013-503 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libXi fixes several integer overflow issues.

  -
    U_0001-integer-overflow-in-XGetDeviceControl-CVE-2013-19
    84-.patch,
    U_0002-integer-overflow-in-XGetFeedbackControl-CVE-2013-
    198.patch,
    U_0003-integer-overflow-in-XGetDeviceDontPropagateList-C
    VE-.patch,
    U_0004-integer-overflow-in-XGetDeviceMotionEvents-CVE-20
    13-.patch,
    U_0005-integer-overflow-in-XIGetProperty-CVE-2013-1984-5
    -8.patch,
    U_0006-integer-overflow-in-XIGetSelectedEvents-CVE-2013-
    198.patch,
    U_0007-Avoid-integer-overflow-in-XGetDeviceProperties-CV
    E-2.patch,
    U_0008-Avoid-integer-overflow-in-XListInputDevices-CVE-2
    013.patch

  - integer overflow in various functions [CVE-2013-1984]
    (bnc#821663, bnc#815451)

  -
    U_0001-sign-extension-issue-in-XListInputDevices-CVE-201
    3-1.patch

  - sign extension issue in XListInputDevices()
    [CVE-2013-1995] (bnc#821663, bnc#815451)

  -
    U_0001-Stack-buffer-overflow-in-XGetDeviceButtonMapping-
    CVE.patch,
    U_0002-memory-corruption-in-_XIPassiveGrabDevice-CVE-201
    3-1.patch,
    U_0003-unvalidated-lengths-in-XQueryDeviceState-CVE-2013
    -19.patch

  - Stack-based buffer overflow in
    XGetDeviceButtonMapping(), memory corruption in
    _XIPassiveGrabDevice(), unvalidated lengths in
    XQueryDeviceState() [CVE-2013-1998] (bnc#821663,
    bnc#815451)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00161.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821663"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/07");
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

if ( rpm_check(release:"SUSE12.2", reference:"libXi-debugsource-1.6.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXi-devel-1.6.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXi6-1.6.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXi6-debuginfo-1.6.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXi-devel-32bit-1.6.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXi6-32bit-1.6.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXi6-debuginfo-32bit-1.6.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXi-debugsource-1.6.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXi-devel-1.6.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXi6-1.6.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXi6-debuginfo-1.6.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXi-devel-32bit-1.6.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXi6-32bit-1.6.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXi6-debuginfo-32bit-1.6.1-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXi-debugsource / libXi-devel / libXi-devel-32bit / libXi6 / etc");
}
