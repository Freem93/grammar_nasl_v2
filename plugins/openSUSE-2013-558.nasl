#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-558.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75075);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/19 15:01:01 $");

  script_bugtraq_id(61002);
  script_osvdb_id(94921);

  script_name(english:"openSUSE Security Update : xorg-x11-server (openSUSE-SU-2013:1148-1)");
  script_summary(english:"Check for the openSUSE-2013-558 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This xorg-x11-server update fixes a DoS vulnerability and adds randr
support.

  - U_os-Reset-input-buffer-s-ignoreBytes-field.patch

  - If a client sends a request larger than
    maxBigRequestSize, the server is supposed to ignore it.
    Before commit cf88363d, the server would simply
    disconnect the client. After that commit, it attempts to
    gracefully ignore the request by remembering how long
    the client specified the request to be, and ignoring
    that many bytes. However, if a client sends a BigReq
    header with a large size and disconnects before actually
    sending the rest of the specified request, the server
    will reuse the ConnectionInput buffer without resetting
    the ignoreBytes field. This makes the server ignore new
    X clients' requests. This fixes that behavior by
    resetting the ignoreBytes field when putting the
    ConnectionInput buffer back on the FreeInputs list.
    (bnc#815583) 

  - u_xserver_xvfb-randr.patch

  - Add randr support to Xvfb (bnc#823410)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823410"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-Xvnc-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-Xvnc-debuginfo-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-debuginfo-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-debugsource-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-extra-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-extra-debuginfo-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xorg-x11-server-sdk-7.6_1.12.3-1.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-7.6_1.13.2-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-debuginfo-7.6_1.13.2-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-debugsource-7.6_1.13.2-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-extra-7.6_1.13.2-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-extra-debuginfo-7.6_1.13.2-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-sdk-7.6_1.13.2-1.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-Xvnc / xorg-x11-Xvnc-debuginfo / xorg-x11-server / etc");
}
