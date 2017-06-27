#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1272 and 
# CentOS Errata and Security Advisory 2013:1272 respectively.
#

include("compat.inc");

if (description)
{
  script_id(69999);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/06 23:41:35 $");

  script_cve_id("CVE-2013-4296", "CVE-2013-4311");
  script_bugtraq_id(62508, 62510);
  script_osvdb_id(97506, 97507);
  script_xref(name:"RHSA", value:"2013:1272");

  script_name(english:"CentOS 6 : libvirt (CESA-2013:1272)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

libvirt invokes the PolicyKit pkcheck utility to handle authorization.
A race condition was found in the way libvirt used this utility,
allowing a local user to bypass intended PolicyKit authorizations or
execute arbitrary commands with root privileges. (CVE-2013-4311)

Note: With this update, libvirt has been rebuilt to communicate with
PolicyKit via a different API that is not vulnerable to the race
condition. The polkit RHSA-2013:1270 advisory must also be installed
to fix the CVE-2013-4311 issue.

An invalid free flaw was found in libvirtd's
remoteDispatchDomainMemoryStats function. An attacker able to
establish a read-only connection to libvirtd could use this flaw to
crash libvirtd. (CVE-2013-4296)

The CVE-2013-4296 issue was discovered by Daniel P. Berrange of Red
Hat.

This update also fixes the following bugs :

* Prior to this update, the libvirtd daemon leaked memory in the
virCgroupMoveTask() function. A fix has been provided which prevents
libvirtd from incorrect management of memory allocations. (BZ#984556)

* Previously, the libvirtd daemon was accessing one byte before the
array in the virCgroupGetValueStr() function. This bug has been fixed
and libvirtd now stays within the array bounds. (BZ#984561)

* When migrating, libvirtd leaked the migration URI (Uniform Resource
Identifier) on destination. A patch has been provided to fix this bug
and the migration URI is now freed correctly. (BZ#984578)

* Updating a network interface using virDomainUpdateDeviceFlags API
failed when a boot order was set for that interface. The update failed
even if the boot order was set in the provided device XML. The
virDomainUpdateDeviceFlags API has been fixed to correctly parse the
boot order specification from the provided device XML and updating
network interfaces with boot orders now works as expected.
(BZ#1003934)

Users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-September/019948.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18646484"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libvirt-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-client-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-devel-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-18.el6_4.14")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-python-0.10.2-18.el6_4.14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
