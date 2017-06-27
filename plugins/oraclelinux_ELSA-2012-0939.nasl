#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0939 and 
# Oracle Linux Security Advisory ELSA-2012-0939 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68561);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2011-4028", "CVE-2011-4029");
  script_bugtraq_id(50193, 50196);
  script_osvdb_id(76668, 76669);
  script_xref(name:"RHSA", value:"2012:0939");

  script_name(english:"Oracle Linux 6 : xorg-x11-server (ELSA-2012-0939)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0939 :

Updated xorg-x11-server packages that fix two security issues and
several bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A flaw was found in the way the X.Org server handled lock files. A
local user with access to the system console could use this flaw to
determine the existence of a file in a directory not accessible to the
user, via a symbolic link attack. (CVE-2011-4028)

A race condition was found in the way the X.Org server managed
temporary lock files. A local attacker could use this flaw to perform
a symbolic link attack, allowing them to make an arbitrary file world
readable, leading to the disclosure of sensitive information.
(CVE-2011-4029)

Red Hat would like to thank the researcher with the nickname vladz for
reporting these issues.

This update also fixes the following bugs :

* Prior to this update, the KDE Display Manager (KDM) could pass
invalid 24bpp pixmap formats to the X server. As a consequence, the X
server could unexpectedly abort. This update modifies the underlying
code to pass the correct formats. (BZ#651934, BZ#722860)

* Prior to this update, absolute input devices, like the stylus of a
graphic tablet, could become unresponsive in the right-most or
bottom-most screen if the X server was configured as a multi-screen
setup through multiple 'Device' sections in the xorg.conf file. This
update changes the screen crossing behavior so that absolute devices
are always mapped across all screens. (BZ#732467)

* Prior to this update, the misleading message 'Session active, not
inhibited, screen idle. If you see this test, your display server is
broken and you should notify your distributor.' could be displayed
after resuming the system or re-enabling the display, and included a
URL to an external web page. This update removes this message.
(BZ#748704)

* Prior to this update, the erroneous input handling code of the
Xephyr server disabled screens on a screen crossing event. The focus
was only on the screen where the mouse was located and only this
screen was updated when the Xephyr nested X server was configured in a
multi-screen setup. This update removes this code and Xephyr now
correctly updates screens in multi-screen setups. (BZ#757792)

* Prior to this update, raw events did not contain relative axis
values. As a consequence, clients which relied on relative values for
functioning did not behave as expected. This update sets the values to
the original driver values instead of the already transformed values.
Now, raw events contain relative axis values as expected. (BZ#805377)

All users of xorg-x11-server are advised to upgrade to these updated
packages, which correct these issues. All running X.Org server
instances must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002912.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xdmx-1.10.6-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xephyr-1.10.6-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xnest-1.10.6-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xorg-1.10.6-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xvfb-1.10.6-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-common-1.10.6-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-devel-1.10.6-1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-source-1.10.6-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
