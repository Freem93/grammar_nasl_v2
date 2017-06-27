#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60682);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2005-4881", "CVE-2009-3228");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"CVE-2005-4881 kernel: netlink: fix numerous padding memleaks

CVE-2009-3228 kernel: tc: uninitialised kernel memory leak

This update fixes the following security issues :

  - multiple, missing initialization flaws were found in the
    Linux kernel. Padding data in several core network
    structures was not initialized properly before being
    sent to user-space. These flaws could lead to
    information leaks. (CVE-2005-4881, CVE-2009-3228,
    Moderate)

This update also fixes the following bugs :

  - a packet duplication issue was fixed via the
    RHSA-2008:0665 update; however, the fix introduced a
    problem for systems using network bonding: Backup slaves
    were unable to receive ARP packets. When using network
    bonding in the 'active-backup' mode and with the
    'arp_validate=3' option, the bonding driver considered
    such backup slaves as being down (since they were not
    receiving ARP packets), preventing successful failover
    to these devices. (BZ#519384)

  - due to insufficient memory barriers in the network code,
    a process sleeping in select() may have missed
    notifications about new data. In rare cases, this bug
    may have caused a process to sleep forever. (BZ#519386)

  - the driver version number in the ata_piix driver was not
    changed between Scientific Linux 4.7 and Scientific
    Linux 4.8, even though changes had been made between
    these releases. This could have prevented the driver
    from loading on systems that check driver versions, as
    this driver appeared older than it was. (BZ#519389)

  - a bug in nlm_lookup_host() could have led to
    un-reclaimed locks on file systems, resulting in the
    umount command failing. This bug could have also
    prevented NFS services from being relocated correctly in
    clustered environments. (BZ#519656)

  - the data buffer ethtool_get_strings() allocated, for the
    igb driver, was smaller than the amount of data that was
    copied in igb_get_strings(), because of a miscalculation
    in IGB_QUEUE_STATS_LEN, resulting in memory corruption.
    This bug could have led to a kernel panic. (BZ#522738)

  - in some situations, write operations to a TTY device
    were blocked even when the O_NONBLOCK flag was used. A
    reported case of this issue occurred when a single TTY
    device was opened by two users (one using blocking mode,
    and the other using non-blocking mode). (BZ#523930)

  - a deadlock was found in the cciss driver. In rare cases,
    this caused an NMI lockup during boot. Messages such as
    'cciss: controller cciss[x] failed, stopping.' and
    'cciss[x]: controller not responding.' may have been
    displayed on the console. (BZ#525725)

  - on 64-bit PowerPC systems, a rollover bug in the ibmveth
    driver could have caused a kernel panic. In a reported
    case, this panic occurred on a system with a large
    uptime and under heavy network load. (BZ#527225)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=1943
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f701e30d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=519384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=519386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=519389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=519656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=522738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=523930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=525725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=527225"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/22");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.15.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.15.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
