#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60515);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-4405", "CVE-2008-4993");

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
"Xen was found to allow unprivileged DomU domains to overwrite xenstore
values which should only be changeable by the privileged Dom0 domain.
An attacker controlling a DomU domain could, potentially, use this
flaw to kill arbitrary processes in Dom0 or trick a Dom0 user into
accessing the text console of a different domain running on the same
host. This update makes certain parts of the xenstore tree read-only
to the unprivileged DomU domains. (CVE-2008-4405)

It was discovered that the qemu-dm.debug script created a temporary
file in /tmp in an insecure way. A local attacker in Dom0 could,
potentially, use this flaw to overwrite arbitrary files via a symlink
attack. Note: This script is not needed in production deployments and
therefore was removed and is not shipped with updated xen packages.
(CVE-2008-4993)

This update also fixes the following bug :

  - xen calculates its running time by adding the
    hypervisor's up-time to the hypervisor's boot-time
    record. In live migrations of para-virtualized guests,
    however, the guest would over-write the new hypervisor's
    boot-time record with the boot-time of the previous
    hypervisor. This caused time-dependent processes on the
    guests to fail (for example, crond would fail to start
    cron jobs). With this update, the new hypervisor's
    boot-time record is no longer over-written during live
    migrations.

The Xen host must be restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0901&L=scientific-linux-errata&T=0&P=586
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fca6725a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen, xen-devel and / or xen-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
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
if (rpm_check(release:"SL5", reference:"xen-3.0.3-64.el5_2.9")) flag++;
if (rpm_check(release:"SL5", reference:"xen-devel-3.0.3-64.el5_2.9")) flag++;
if (rpm_check(release:"SL5", reference:"xen-libs-3.0.3-64.el5_2.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
