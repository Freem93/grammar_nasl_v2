#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0140 and 
# CentOS Errata and Security Advisory 2006:0140 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21881);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2002-2185", "CVE-2004-1057", "CVE-2005-2708", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3044", "CVE-2005-3180", "CVE-2005-3275", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858");
  script_bugtraq_id(14902);
  script_osvdb_id(13897, 19597, 19598, 19925, 20163, 20676, 21279, 21285, 21516, 22506, 22507, 22509, 22668);
  script_xref(name:"RHSA", value:"2006:0140");

  script_name(english:"CentOS 3 : kernel (CESA-2006:0140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in the Red
Hat Enterprise Linux 3 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

  - a flaw in network IGMP processing that a allowed a
    remote user on the local network to cause a denial of
    service (disabling of multicast reports) if the system
    is running multicast applications (CVE-2002-2185,
    moderate)

  - a flaw in remap_page_range() with O_DIRECT writes that
    allowed a local user to cause a denial of service
    (crash) (CVE-2004-1057, important)

  - a flaw in exec() handling on some 64-bit architectures
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-2708, important)

  - a flaw in procfs handling during unloading of modules
    that allowed a local user to cause a denial of service
    or potentially gain privileges (CVE-2005-2709, moderate)

  - a flaw in IPv6 network UDP port hash table lookups that
    allowed a local user to cause a denial of service (hang)
    (CVE-2005-2973, important)

  - a flaw in 32-bit-compat handling of the TIOCGDEV ioctl
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-3044, important)

  - a network buffer info leak using the orinoco driver that
    allowed a remote user to possibly view uninitialized
    data (CVE-2005-3180, important)

  - a flaw in IPv4 network TCP and UDP netfilter handling
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-3275, important)

  - a flaw in the IPv6 flowlabel code that allowed a local
    user to cause a denial of service (crash)
    (CVE-2005-3806, important)

  - a flaw in network ICMP processing that allowed a local
    user to cause a denial of service (memory exhaustion)
    (CVE-2005-3848, important)

  - a flaw in file lease time-out handling that allowed a
    local user to cause a denial of service (log file
    overflow) (CVE-2005-3857, moderate)

  - a flaw in network IPv6 xfrm handling that allowed a
    local user to cause a denial of service (memory
    exhaustion) (CVE-2005-3858, important)

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architecture and
configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb257c83"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea3abe10"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63ba8875"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-37.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-37.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
