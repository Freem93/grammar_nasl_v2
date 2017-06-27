#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0391 and 
# CentOS Errata and Security Advisory 2011:0391 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53577);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/28 23:54:24 $");

  script_cve_id("CVE-2011-1146");
  script_xref(name:"RHSA", value:"2011:0391");

  script_name(english:"CentOS 5 : libvirt (CESA-2011:0391)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remotely managing virtualized
systems.

It was found that several libvirt API calls did not honor the
read-only permission for connections. A local attacker able to
establish a read-only connection to libvirtd on a server could use
this flaw to execute commands that should be restricted to read-write
connections, possibly leading to a denial of service or privilege
escalation. (CVE-2011-1146)

Note: Previously, using rpmbuild without the '--define 'rhel 5''
option to build the libvirt source RPM on Red Hat Enterprise Linux 5
failed with a 'Failed build dependencies' error for the
device-mapper-devel package, as this -devel sub-package is not
available on Red Hat Enterprise Linux 5. With this update, the -devel
sub-package is no longer checked by default as a dependency when
building on Red Hat Enterprise Linux 5, allowing the libvirt source
RPM to build as expected.

All libvirt users are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing the updated packages, libvirtd must be restarted ('service
libvirtd restart') for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?591f936f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32d3289f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libvirt-0.8.2-15.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-devel-0.8.2-15.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-python-0.8.2-15.el5_6.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
