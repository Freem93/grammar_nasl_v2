#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0705 and 
# CentOS Errata and Security Advisory 2007:0705 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43648);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-1217", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3851");
  script_bugtraq_id(24376, 24389, 25244, 25263, 25672);
  script_osvdb_id(37112, 37113, 37123, 37124, 37285);
  script_xref(name:"RHSA", value:"2007:0705");

  script_name(english:"CentOS 5 : kernel (CESA-2007:0705)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix various security issues in the Red
Hat Enterprise Linux 5 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the following security
issues :

* a flaw in the DRM driver for Intel graphics cards that allowed a
local user to access any part of the main memory. To access the DRM
functionality a user must have access to the X server which is granted
through the graphical login. This also only affected systems with an
Intel 965 or later graphic chipset. (CVE-2007-3851, Important)

* a flaw in the VFAT compat ioctl handling on 64-bit systems that
allowed a local user to corrupt a kernel_dirent struct and cause a
denial of service (system crash). (CVE-2007-2878, Important)

* a flaw in the connection tracking support for SCTP that allowed a
remote user to cause a denial of service by dereferencing a NULL
pointer. (CVE-2007-2876, Important)

* flaw in the CIFS filesystem which could cause the umask values of a
process to not be honored. This affected CIFS filesystems where the
Unix extensions are supported. (CVE-2007-3740, Important)

* a flaw in the stack expansion when using the hugetlb kernel on
PowerPC systems that allowed a local user to cause a denial of
service. (CVE-2007-3739, Moderate)

* a flaw in the ISDN CAPI subsystem that allowed a remote user to
cause a denial of service or potential remote access. Exploitation
would require the attacker to be able to send arbitrary frames over
the ISDN network to the victim's machine. (CVE-2007-1217, Moderate)

* a flaw in the cpuset support that allowed a local user to obtain
sensitive information from kernel memory. To exploit this the cpuset
filesystem would have to already be mounted. (CVE-2007-2875, Moderate)

* a flaw in the CIFS handling of the mount option 'sec=' that didn't
enable integrity checking and didn't produce any error message.
(CVE-2007-3843, Low)

Red Hat Enterprise Linux 5 users are advised to upgrade to these
packages, which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeff09e3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014197.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0facab31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-8.1.10.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-8.1.10.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-8.1.10.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-8.1.10.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-8.1.10.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-8.1.10.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-8.1.10.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-8.1.10.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
