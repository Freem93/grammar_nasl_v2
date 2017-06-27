#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1620 and 
# CentOS Errata and Security Advisory 2013:1620 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79168);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/12 17:31:56 $");

  script_cve_id("CVE-2013-1940");
  script_bugtraq_id(59282);
  script_osvdb_id(92518);
  script_xref(name:"RHSA", value:"2013:1620");

  script_name(english:"CentOS 6 : xorg-x11-server (CESA-2013:1620)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ad81f75"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xdmx-1.13.0-23.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xephyr-1.13.0-23.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xnest-1.13.0-23.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xorg-1.13.0-23.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xvfb-1.13.0-23.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-common-1.13.0-23.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-devel-1.13.0-23.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-source-1.13.0-23.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
