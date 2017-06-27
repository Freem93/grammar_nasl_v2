#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61280);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2012-0029");

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

A heap overflow flaw was found in the way QEMU emulated the e1000
network interface card. A privileged guest user in a virtual machine
whose network interface is configured to use the e1000 emulated driver
could use this flaw to crash QEMU or, possibly, escalate their
privileges on the host. (CVE-2012-0029)

This update also fixes the following bugs :

  - Adding support for jumbo frames introduced incorrect
    network device expansion when a bridge is created. The
    expansion worked correctly with the default
    configuration, but could have caused network setup
    failures when a user-defined network script was used.
    This update changes the expansion so network setup will
    not fail, even when a user-defined network script is
    used.

  - A bug was found in xenconsoled, the Xen hypervisor
    console daemon. If timestamp logging for this daemon was
    enabled (using both the
    XENCONSOLED_TIMESTAMP_HYPERVISOR_LOG and
    XENCONSOLED_TIMESTAMP_GUEST_LOG options in
    '/etc/sysconfig/xend'), xenconsoled could crash if the
    guest emitted a lot of information to its serial console
    in a short period of time. Eventually, the guest would
    freeze after the console buffer was filled due to the
    crashed xenconsoled. Timestamp logging is disabled by
    default.

All xen users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=2272
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f40c7a2a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
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
if (rpm_check(release:"SL5", reference:"xen-3.0.3-135.el5_8.2")) flag++;
if (rpm_check(release:"SL5", reference:"xen-debuginfo-3.0.3-135.el5_8.2")) flag++;
if (rpm_check(release:"SL5", reference:"xen-devel-3.0.3-135.el5_8.2")) flag++;
if (rpm_check(release:"SL5", reference:"xen-libs-3.0.3-135.el5_8.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
