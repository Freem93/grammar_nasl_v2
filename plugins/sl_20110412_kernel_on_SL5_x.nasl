#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61018);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-4346", "CVE-2011-0521", "CVE-2011-0710", "CVE-2011-1010", "CVE-2011-1090", "CVE-2011-1478");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - A missing boundary check was found in the dvb_ca_ioctl()
    function in the Linux kernel's av7110 module. On systems
    that use old DVB cards that require the av7110 module, a
    local, unprivileged user could use this flaw to cause a
    denial of service or escalate their privileges.
    (CVE-2011-0521, Important)

  - An inconsistency was found in the interaction between
    the Linux kernel's method for allocating NFSv4 (Network
    File System version 4) ACL data and the method by which
    it was freed. This inconsistency led to a kernel panic
    which could be triggered by a local, unprivileged user
    with files owned by said user on an NFSv4 share.
    (CVE-2011-1090, Moderate)

  - A NULL pointer dereference flaw was found in the Generic
    Receive Offload (GRO) functionality in the Linux
    kernel's networking implementation. If both GRO and
    promiscuous mode were enabled on an interface in a
    virtual LAN (VLAN), it could result in a denial of
    service when a malformed VLAN frame is received on that
    interface. (CVE-2011-1478, Moderate)

  - A missing security check in the Linux kernel's
    implementation of the install_special_mapping() function
    could allow a local, unprivileged user to bypass the
    mmap_min_addr protection mechanism. (CVE-2010-4346, Low)

  - An information leak was found in the Linux kernel's
    task_show_regs() implementation. On IBM S/390 systems, a
    local, unprivileged user could use this flaw to read
    /proc/[PID]/status files, allowing them to discover the
    CPU register values of processes. (CVE-2011-0710, Low)

  - A missing validation check was found in the Linux
    kernel's mac_partition() implementation, used for
    supporting file systems created on Mac OS operating
    systems. A local attacker could use this flaw to cause a
    denial of service by mounting a disk that contains
    specially crafted partitions. (CVE-2011-1010, Low)

This update also fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=1730
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cb1fdd4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-238.9.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-238.9.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
