#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(92859);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2016-5403");

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
"Security Fix(es) :

  - Quick emulator(Qemu) built with the virtio framework is
    vulnerable to an unbounded memory allocation issue. It
    was found that a malicious guest user could submit more
    requests than the virtqueue size permits. Processing a
    request allocates a VirtQueueElement and therefore
    causes unbounded memory allocation on the host
    controlled by the guest. (CVE-2016-5403)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1608&L=scientific-linux-errata&F=&S=&P=4542
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9deff35"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-api-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-api-devel-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-cli-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-client-xlators-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-devel-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-fuse-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-ganesha-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-libs-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-rdma-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-resource-agents-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"glusterfs-server-3.7.5-19.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"nfs-ganesha-2.2.0-12.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"nfs-ganesha-gluster-2.2.0-12.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"python-argparse-1.2.1-2.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"pyxattr-0.5.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-guest-agent-0.12.1.2-2.491.el6_8.3")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.491.el6_8.3")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.491.el6_8.3")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-kvm-debuginfo-0.12.1.2-2.491.el6_8.3")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.491.el6_8.3")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"userspace-rcu-0.7.9-2.el6rhs")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"userspace-rcu-devel-0.7.9-2.el6rhs")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
