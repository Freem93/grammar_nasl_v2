#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61163);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/02 10:44:39 $");

  script_cve_id("CVE-2011-3346");

  script_name(english:"Scientific Linux Security Update : xen on SL5.x i386/x86_64");
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
"The xen packages contain administration tools and the xend service for
managing the kernel-xen kernel for virtualization on Scientific Linux.

A buffer overflow flaw was found in the Xen hypervisor SCSI subsystem
emulation. An unprivileged, local guest user could provide a large
number of bytes that are used to zero out a fixed-sized buffer via a
SAI READ CAPACITY SCSI command, overwriting memory and causing the
guest to crash. (CVE-2011-3346)

This update also fixes the following bugs :

  - Prior to this update, the vif-bridge script used a
    maximum transmission unit (MTU) of 1500 for a new
    Virtual Interface (VIF). As a result, the MTU of the VIF
    could differ from that of the target bridge. This update
    fixes the VIF hot-plug script so that the default MTU
    for new VIFs will match that of the target Xen
    hypervisor bridge. In combination with a new enough
    kernel, this enables the use of jumbo frames in Xen
    hypervisor guests.

  - Prior to this update, the network-bridge script set the
    MTU of the bridge to 1500. As a result, the MTU of the
    Xen hypervisor bridge could differ from that of the
    physical interface. This update fixes the network script
    so the MTU of the bridge can be set higher than 1500,
    thus also providing support for jumbo frames. Now, the
    MTU of the Xen hypervisor bridge will match that of the
    physical interface.

  - Scientific Linux 5.6 introduced an optimized migration
    handling that speeds up the migration of guests with
    large memory. However, the new migration procedure can
    theoretically cause data corruption. While no cases were
    observed in practice, with this update, the xend daemon
    properly waits for correct device release before the
    guest is started on a destination machine, thus fixing
    this bug.

Note: Before a guest is using a new enough kernel, the MTU of the VIF
will drop back to 1500 (if it was set higher) after migration.

All xen users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the xend service must be restarted for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1110&L=scientific-linux-errata&T=0&P=2536
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?310d69db"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/24");
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
if (rpm_check(release:"SL5", reference:"xen-3.0.3-132.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"xen-debuginfo-3.0.3-132.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"xen-devel-3.0.3-132.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"xen-libs-3.0.3-132.el5_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
