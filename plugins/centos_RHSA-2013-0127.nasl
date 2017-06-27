#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0127 and 
# CentOS Errata and Security Advisory 2013:0127 respectively.
#

include("compat.inc");

if (description)
{
  script_id(63572);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/12 17:08:52 $");

  script_cve_id("CVE-2012-2693");
  script_bugtraq_id(54126);
  script_osvdb_id(83157);
  script_xref(name:"RHSA", value:"2013:0127");

  script_name(english:"CentOS 5 : libvirt (CESA-2013:0127)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.

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

This update also fixes the following bugs :

* Previously, the libvirtd library failed to set the autostart flags
for already defined QEMU domains. This bug has been fixed, and the
domains can now be successfully marked as autostarted. (BZ#675319)

* Prior to this update, the virFileAbsPath() function was not taking
into account the slash ('/') directory separator when allocating
memory for combining the cwd() function and a path. This behavior
could lead to a memory corruption. With this update, a transformation
to the virAsprintff() function has been introduced into
virFileAbsPath(). As a result, the aforementioned behavior no longer
occurs. (BZ#680289)

* With this update, a man page of the virsh user interface has been
enhanced with information on the 'domxml-from-native' and
'domxml-to-native' commands. A correct notation of the format argument
has been clarified. As a result, confusion is avoided when setting the
format argument in the described commands. (BZ#783001)

All users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9c05f93"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-January/000384.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37c21eaf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libvirt-0.8.2-29.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-devel-0.8.2-29.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-python-0.8.2-29.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
