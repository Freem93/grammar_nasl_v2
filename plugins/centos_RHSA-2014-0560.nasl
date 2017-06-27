#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0560 and 
# CentOS Errata and Security Advisory 2014:0560 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(74226);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/14 14:19:28 $");

  script_cve_id("CVE-2014-0179", "CVE-2014-5177");
  script_bugtraq_id(67289);
  script_xref(name:"RHSA", value:"2014:0560");

  script_name(english:"CentOS 6 : libvirt (CESA-2014:0560)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue and three bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

It was found that libvirt passes the XML_PARSE_NOENT flag when parsing
XML documents using the libxml2 library, in which case all XML
entities in the parsed documents are expanded. A user able to force
libvirtd to parse an XML document with an entity pointing to a special
file that blocks on read access could use this flaw to cause libvirtd
to hang indefinitely, resulting in a denial of service on the system.
(CVE-2014-0179)

Red Hat would like to thank the upstream Libvirt project for reporting
this issue. Upstream acknowledges Daniel P. Berrange and Richard Jones
as the original reporters.

This update also fixes the following bugs :

* When hot unplugging a virtual CPU (vCPU), libvirt kept a pointer to
already freed memory if the vCPU was pinned to a host CPU.
Consequently, when reading the CPU pinning information, libvirt
terminated unexpectedly due to an attempt to access this memory. This
update ensures that libvirt releases the pointer to the previously
allocated memory when a vCPU is being hot unplugged, and it no longer
crashes in this situation. (BZ#1091206)

* Previously, libvirt passed an incorrect argument to the 'tc' command
when setting quality of service (QoS) on a network interface
controller (NIC). As a consequence, QoS was applied only to IP
traffic. With this update, libvirt constructs the 'tc' command
correctly so that QoS is applied to all traffic as expected.
(BZ#1096806)

* When using the sanlock daemon for managing access to shared storage,
libvirt expected all QEMU domains to be registered with sanlock.
However, if a QEMU domain was started prior to enabling sanlock, the
domain was not registered with sanlock. Consequently, migration of a
virtual machine (VM) from such a QEMU domain failed with a libvirt
error. With this update, libvirt verifies whether a QEMU domain
process is registered with sanlock before it starts working with the
domain, ensuring that migration of virtual machines works as expected.
(BZ#1097227)

All libvirt users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2014-May/020322.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/29");
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
if (rpm_check(release:"CentOS-6", reference:"libvirt-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-client-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-devel-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvirt-python-0.10.2-29.el6_5.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
