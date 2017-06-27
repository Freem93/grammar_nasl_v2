#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96599);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/18 14:49:21 $");

  script_cve_id("CVE-2016-6828", "CVE-2016-7117", "CVE-2016-9555");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64");
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
"To see the complete list of bug fixes, users are directed to the
related Knowledge Article :

Security Fix(es) :

  - A use-after-free vulnerability was found in the kernel's
    socket recvmmsg subsystem. This may allow remote
    attackers to corrupt memory and may allow execution of
    arbitrary code. This corruption takes place during the
    error handling routines within __sys_recvmmsg()
    function. (CVE-2016-7117, Important)

  - A use-after-free vulnerability was found in
    tcp_xmit_retransmit_queue and other tcp_* functions.
    This condition could allow an attacker to send an
    incorrect selective acknowledgment to existing
    connections, possibly resetting a connection.
    (CVE-2016-6828, Moderate)

  - A flaw was found in the Linux kernel's implementation of
    the SCTP protocol. A remote attacker could trigger an
    out-of-bounds read with an offset of up to 64kB
    potentially causing the system to crash. (CVE-2016-9555,
    Moderate)

Bug Fix(es) :

  - Previously, the performance of Internet Protocol over
    InfiniBand (IPoIB) was suboptimal due to a conflict of
    IPoIB with the Generic Receive Offload (GRO)
    infrastructure. With this update, the data cached by the
    IPoIB driver has been moved from a control block into
    the IPoIB hard header, thus avoiding the GRO problem and
    the corruption of IPoIB address information. As a
    result, the performance of IPoIB has been improved.

  - Previously, when a virtual machine (VM) with
    PCI-Passthrough interfaces was recreated, a race
    condition between the eventfd daemon and the virqfd
    daemon occurred. Consequently, the operating system
    rebooted. This update fixes the race condition. As a
    result, the operating system no longer reboots in the
    described situation.

  - Previously, a packet loss occurred when the team driver
    in round-robin mode was sending a large number of
    packets. This update fixes counting of the packets in
    the round-robin runner of the team driver, and the
    packet loss no longer occurs in the described situation.

  - Previously, the virtual network devices contained in the
    deleted namespace could be deleted in any order. If the
    loopback device was not deleted as the last item, other
    netns devices, such as vxlan devices, could end up with
    dangling references to the loopback device.
    Consequently, deleting a network namespace (netns)
    occasionally ended by a kernel oops. With this update,
    the underlying source code has been fixed to ensure the
    correct order when deleting the virtual network devices
    on netns deletion. As a result, the kernel oops no
    longer occurs under the described circumstances.

  - Previously, a Kabylake system with a Sunrise Point
    Platform Controller Hub (PCH) with a PCI device ID of
    0xA149 showed the following warning messages during the
    boot :

'Unknown Intel PCH (0xa149) detected.' 'Warning: Intel Kabylake
processor with unknown PCH - this hardware has not undergone testing
...'

The messages were shown because this PCH was not properly recognized.
With this update, the problem has been fixed, and the operating system
now boots without displaying the warning messages.

  - Previously, the operating system occasionally became
    unresponsive after a long run. This was caused by a race
    condition between the try_to_wake_up() function and a
    woken up task in the core scheduler. With this update,
    the race condition has been fixed, and the operating
    system no longer locks up in the described scenario."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1701&L=scientific-linux-errata&F=&S=&P=9762
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c9770c7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-514.6.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-514.6.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
