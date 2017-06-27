#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83451);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/05/28 15:58:00 $");

  script_cve_id("CVE-2015-3331");

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
"  - A buffer overflow flaw was found in the way the Linux
    kernel's Intel AES-NI instructions optimized version of
    the RFC4106 GCM mode decryption functionality handled
    fragmented packets. A remote attacker could use this
    flaw to crash, or potentially escalate their privileges
    on, a system over a connection with an active AEC-GCM
    mode IPSec security association. (CVE-2015-3331,
    Important)

This update also fixes the following bugs :

  - Previously, the kernel audit subsystem did not correctly
    track file path names which could lead to empty, or
    '(null)' path names in the PATH audit records. This
    update fixes the bug by correctly tracking file path
    names and displaying the names in the audit PATH
    records.

  - Due to a change in the internal representation of field
    types, AUDIT_LOGINUID set to -1 (4294967295) by the
    audit API was asymmetrically converted to an
    AUDIT_LOGINUID_SET field with a value of 0, unrecognized
    by an older audit API. To fix this bug, the kernel takes
    note about the way the rule has been formulated and
    reports the rule in the originally given form. As a
    result, older versions of audit provide a report as
    expected, in the AUDIT_LOGINUID field type form, whereas
    the newer versions can migrate to the new
    AUDIT_LOGINUID_SET filed type.

  - The GFS2 file system 'Splice Read' operation, which is
    used for the sendfile() function, was not properly
    allocating a required multi-block reservation structure
    in memory. Consequently, when the GFS2 block allocator
    was called to assign blocks of data, it attempted to
    dereference the structure, which resulted in a kernel
    panic. With this update, 'Splice read' operation
    properly allocates the necessary reservation structure
    in memory prior to calling the block allocator, and
    sendfile() thus works properly for GFS2.

  - Moving an Open vSwitch (OVS) internal vport to a
    different net name space and subsequently deleting that
    name space led to a kernel panic. This bug has been
    fixed by removing the OVS internal vport at net name
    space deletion.

  - Previously, the kernel audit subsystem was not correctly
    handling file and directory moves, leading to audit
    records that did not match the audit file watches. This
    fix correctly handles moves such that the audit file
    watches work correctly.

  - Due to a regression, the crypto adapter could not be set
    online. A patch has been provided that fixes the device
    registration process so that the device can be used also
    before the registration process is completed, thus
    fixing this bug.

  - Due to incorrect calculation for entropy during the
    entropy addition, the amount of entropy in the
    /dev/random file could be overestimated. The formula for
    the entropy addition has been changed, thus fixing this
    bug.

  - Previously, the ansi_cprng and drbg utilities did not
    obey the call convention and returned the positive value
    on success instead of the correct value of zero.
    Consequently, Internet Protocol Security (IPsec)
    terminated unexpectedly when ansi_cprng or drbg were
    used. With this update, ansi_cprng and drbg have been
    changed to return zero on success, and IPsec now
    functions correctly.

  - Due to a failure to clear the timestamp flag when
    reusing a tx descriptor in the mlx4_en driver, programs
    that did not request a hardware timestamp packet on
    their sent data received it anyway, resulting in
    unexpected behavior in certain applications. With this
    update, when reusing the tx descriptor in the mlx4_en
    driver in the aforementioned situation, the hardware
    timestamp flag is cleared, and applications now behave
    as expected.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1505&L=scientific-linux-errata&T=0&P=1369
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef671a21"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-229.4.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
