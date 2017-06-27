#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1620. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71011);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-1940");
  script_bugtraq_id(59282);
  script_osvdb_id(92518);
  script_xref(name:"RHSA", value:"2013:1620");

  script_name(english:"RHEL 6 : xorg-x11-server (RHSA-2013:1620)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix one security issue and
several bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A flaw was found in the way the X.org X11 server registered new hot
plugged devices. If a local user switched to a different session and
plugged in a new device, input from that device could become available
in the previous session, possibly leading to information disclosure.
(CVE-2013-1940)

This issue was found by David Airlie and Peter Hutterer of Red Hat.

This update also fixes the following bugs :

* A previous upstream patch modified the Xephyr X server to be
resizeable, however, it did not enable the resize functionality by
default. As a consequence, X sandboxes were not resizeable on Red Hat
Enterprise Linux 6.4 and later. This update enables the resize
functionality by default so that X sandboxes can now be resized as
expected. (BZ#915202)

* In Red Hat Enterprise Linux 6, the X Security extension
(XC-SECURITY) has been disabled and replaced by X Access Control
Extension (XACE). However, XACE does not yet include functionality
that was previously available in XC-SECURITY. With this update,
XC-SECURITY is enabled in the xorg-x11-server spec file on Red Hat
Enterprise Linux 6. (BZ#957298)

* Upstream code changes to extension initialization accidentally
disabled the GLX extension in Xvfb (the X virtual frame buffer),
rendering headless 3D applications not functional. An upstream patch
to this problem has been backported so the GLX extension is enabled
again, and applications relying on this extension work as expected.
(BZ#969538)

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1940.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1620.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1620";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xdmx-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xdmx-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xephyr-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xephyr-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xnest-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xnest-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xorg-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xvfb-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xvfb-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-common-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-common-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-common-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-debuginfo-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-debuginfo-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-debuginfo-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-devel-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-devel-1.13.0-23.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xorg-x11-server-source-1.13.0-23.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
  }
}
