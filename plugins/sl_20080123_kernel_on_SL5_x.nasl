#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60351);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-3104", "CVE-2007-5904", "CVE-2007-6206", "CVE-2007-6416", "CVE-2008-0001");

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
"These new kernel packages fix the following security issues :

A flaw was found in the virtual filesystem (VFS). An unprivileged
local user could truncate directories to which they had write
permission; this could render the contents of the directory
inaccessible. (CVE-2008-0001, Important)

A flaw was found in the Xen PAL emulation on Intel 64 platforms. A
guest Hardware-assisted virtual machine (HVM) could read the arbitrary
physical memory of the host system, which could make information
available to unauthorized users. (CVE-2007-6416, Important)

A flaw was found in the way core dump files were created. If a local
user can get a root-owned process to dump a core file into a
directory, which the user has write access to, they could gain read
access to that core file, potentially containing sensitive
information. (CVE-2007-6206, Moderate)

A buffer overflow flaw was found in the CIFS virtual file system. A
remote,authenticated user could issue a request that could lead to a
denial of service. (CVE-2007-5904, Moderate)

A flaw was found in the 'sysfs_readdir' function. A local user could
create a race condition which would cause a denial of service (kernel
oops). (CVE-2007-3104, Moderate)

As well, these updated packages fix the following bugs :

  - running the 'strace -f' command caused strace to hang,
    without displaying information about child processes.

  - unmounting an unresponsive, interruptable NFS mount, for
    example, one mounted with the 'intr' option, may have
    caused a system crash.

  - a bug in the s2io.ko driver prevented VLAN devices from
    being added. Attempting to add a device to a VLAN, for
    example, running the 'vconfig add [device-name]
    [vlan-id]' command caused vconfig to fail.

  - tux used an incorrect open flag bit. This caused
    problems when building packages in a chroot environment,
    such as mock, which is used by the koji build system."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0801&L=scientific-linux-errata&T=0&P=2087
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17442fda"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-53.1.6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
