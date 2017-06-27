#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(66780);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/04 10:58:40 $");

  script_cve_id("CVE-2013-2007");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL6.x i386/x86_64");
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
"It was found that QEMU Guest Agent (the 'qemu-ga' service) created
certain files with world-writable permissions when run in daemon mode
(the default mode). An unprivileged guest user could use this flaw to
consume all free space on the partition containing the qemu-ga log
file, or modify the contents of the log. When a UNIX domain socket
transport was explicitly configured to be used (not the default), an
unprivileged guest user could potentially use this flaw to escalate
their privileges in the guest. This update requires manual action.
Refer below for details. (CVE-2013-2007)

This update does not change the permissions of the existing log file
or the UNIX domain socket. For these to be changed, stop the qemu-ga
service, and then manually remove all 'group' and 'other' permissions
on the affected files, or remove the files.

Note that after installing this update, files created by the
guest-file- open QEMU Monitor Protocol (QMP) command will still
continue to be created with world-writable permissions for backwards
compatibility.

This update also fixes the following bugs :

  - Previously, due to integer overflow in code
    calculations, the qemu-kvm utility was reporting
    incorrect memory size on QMP events when using the
    virtio balloon driver with more than 4 GB of memory.
    This update fixes the overflow in the code and qemu-kvm
    works as expected in the described scenario.

  - When the set_link flag is set to 'off' to change the
    status of a network card, the status is changed to
    'down' on the respective guest. Previously, with certain
    network cards, when such a guest was restarted, the
    status of the network card was unexpectedly reset to
    'up', even though the network was unavailable. A patch
    has been provided to address this bug and the link
    status change is now preserved across restarts for all
    network cards.

After installing this update, shut down all running virtual machines.
Once all virtual machines have shut down, start them again for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1306&L=scientific-linux-errata&T=0&P=340
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b53c69d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"qemu-guest-agent-0.12.1.2-2.355.el6_4.5")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-guest-agent-win32-0.12.1.2-2.355.el6_4.5")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.355.el6_4.5")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.355.el6_4.5")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-kvm-debuginfo-0.12.1.2-2.355.el6_4.5")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.355.el6_4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
