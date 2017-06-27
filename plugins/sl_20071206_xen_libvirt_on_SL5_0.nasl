#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60325);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_name(english:"Scientific Linux Security Update : xen/libvirt on SL5.0 i386/x86_64");
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
"NOTE1: The xen update needs to be applied with the new kernel
kernel-2.6.18-53.1.4.el5. Because a kernel does not automatically get
updated, but the xen libraries do (by default) it is best to upgrade
them both at the same time, and then reboot into the new kernel.

Updating both the kernel and xen is because the new kernel has changed
the way that it works with xen. So upgrading and booting into the new
kernel will break your old xen. And updating xen and trying to restart
xen domains in your old kernel will not work either.

Updating the xen libraries will not affect currently running virtual
machines, but will prevent any new ones being started or rebooted,
until you have booted into the new kernel.

NOTE2: This xen/kernel update is only really needed for the master
virtual machine (Dom 0). Virtual machines can update their kernels
without any problems."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0712&L=scientific-linux-errata&T=0&P=889
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3abece31"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libvirt-0.2.3-9.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-devel-0.2.3-9.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-python-0.2.3-9.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-virtinst-0.103.0-3.sl5.2")) flag++;
if (rpm_check(release:"SL5", reference:"virt-manager-0.4.0-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xen-3.0.3-41.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xen-devel-3.0.3-41.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xen-libs-3.0.3-41.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
