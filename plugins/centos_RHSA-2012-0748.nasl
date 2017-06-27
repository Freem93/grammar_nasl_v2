#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0748 and 
# CentOS Errata and Security Advisory 2012:0748 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59918);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/28 23:58:55 $");

  script_cve_id("CVE-2012-2693");
  script_osvdb_id(83157);
  script_xref(name:"RHSA", value:"2012:0748");

  script_name(english:"CentOS 6 : libvirt (CESA-2012:0748)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue, multiple bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

Bus and device IDs were ignored when attempting to attach multiple USB
devices with identical vendor or product IDs to a guest. This could
result in the wrong device being attached to a guest, giving that
guest root access to the device. (CVE-2012-2693)

These updated libvirt packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.3
Technical Notes for information on the most significant of these
changes.

All users of libvirt are advised to upgrade to these updated packages,
which fix these issues and add these enhancements. After installing
the updated packages, libvirtd must be restarted ('service libvirtd
restart') for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018709.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?637cea2e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libvirt-0.9.10-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-client-0.9.10-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-devel-0.9.10-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-lock-sanlock-0.9.10-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-python-0.9.10-21.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
