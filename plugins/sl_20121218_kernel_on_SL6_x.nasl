#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63313);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id("CVE-2009-4307", "CVE-2011-4131", "CVE-2012-2100", "CVE-2012-2375", "CVE-2012-4444", "CVE-2012-4565", "CVE-2012-5517");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
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

  - It was found that a previous update did not correctly
    fix the CVE-2011-4131 issue. A malicious Network File
    System version 4 (NFSv4) server could return a crafted
    reply to a GETACL request, causing a denial of service
    on the client. (CVE-2012-2375, Moderate)

  - A divide-by-zero flaw was found in the TCP Illinois
    congestion control algorithm implementation in the Linux
    kernel. If the TCP Illinois congestion control algorithm
    were in use (the sysctl net.ipv4.tcp_congestion_control
    variable set to 'illinois'), a local, unprivileged user
    could trigger this flaw and cause a denial of service.
    (CVE-2012-4565, Moderate)

  - A NULL pointer dereference flaw was found in the way a
    new node's hot added memory was propagated to other
    nodes' zonelists. By utilizing this newly added memory
    from one of the remaining nodes, a local, unprivileged
    user could use this flaw to cause a denial of service.
    (CVE-2012-5517, Moderate)

  - It was found that the initial release of Scientific
    Linux 6 did not correctly fix the CVE-2009-4307 issue, a
    divide-by-zero flaw in the ext4 file system code. A
    local, unprivileged user with the ability to mount an
    ext4 file system could use this flaw to cause a denial
    of service. (CVE-2012-2100, Low)

  - A flaw was found in the way the Linux kernel's IPv6
    implementation handled overlapping, fragmented IPv6
    packets. A remote attacker could potentially use this
    flaw to bypass protection mechanisms (such as a firewall
    or intrusion detection system (IDS)) when sending
    network packets to a target system. (CVE-2012-4444, Low)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1212&L=scientific-linux-errata&T=0&P=1179
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62a6b25f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-279.19.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-279.19.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
