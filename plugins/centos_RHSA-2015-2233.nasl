#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2233 and 
# CentOS Errata and Security Advisory 2015:2233 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87144);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/21 14:22:25 $");

  script_cve_id("CVE-2014-8240", "CVE-2014-8241");
  script_osvdb_id(113009, 113010);
  script_xref(name:"RHSA", value:"2015:2233");

  script_name(english:"CentOS 7 : tigervnc (CESA-2015:2233)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tigervnc packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Virtual Network Computing (VNC) is a remote display system which
allows users to view a computing desktop environment not only on the
machine where it is running, but from anywhere on the Internet and
from a wide variety of machine architectures. TigerVNC is a suite of
VNC servers and clients. The tigervnc packages contain a client which
allows users to connect to other desktops running a VNC server.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way TigerVNC handled screen sizes. A malicious VNC server
could use this flaw to cause a client to crash or, potentially,
execute arbitrary code on the client. (CVE-2014-8240)

A NULL pointer dereference flaw was found in TigerVNC's XRegion. A
malicious VNC server could use this flaw to cause a client to crash.
(CVE-2014-8241)

The tigervnc packages have been upgraded to upstream version 1.3.1,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#1199453)

This update also fixes the following bug :

* The position of the mouse cursor in the VNC session was not
correctly communicated to the VNC viewer, resulting in cursor
misplacement. The method of displaying the remote cursor has been
changed, and cursor movements on the VNC server are now accurately
reflected on the VNC client. (BZ#1100661)

All tigervnc users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f394ec9b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tigervnc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-1.3.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-icons-1.3.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-license-1.3.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-1.3.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-applet-1.3.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.3.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-module-1.3.1-3.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
