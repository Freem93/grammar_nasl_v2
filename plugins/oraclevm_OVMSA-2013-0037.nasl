#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0037.
#

include("compat.inc");

if (description)
{
  script_id(79506);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-1918", "CVE-2013-1952", "CVE-2013-1964");
  script_bugtraq_id(59293, 59615, 59617);
  script_osvdb_id(92565);

  script_name(english:"OracleVM 3.1 : xen (OVMSA-2013-0037)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - VT-d: don't permit SVT_NO_VERIFY entries for known
    device types Only in cases where we don't know what to
    do we should leave the IRTE blank (suppressing all
    validation), but we should always log a warning in those
    cases (as being insecure). This is CVE-2013-1952 /
    XSA-49.

  - x86: make page table handling error paths preemptible
    ... as they may take significant amounts of time. This
    requires cloning the tweaked continuation logic from
    do_mmuext_op to do_mmu_update. Note that in
    mod_l[34]_entry a negative 'preemptible' value gets
    passed to put_page_from_l[34]e now, telling the callee
    to store the respective page in
    current->arch.old_guest_table (for a hypercall
    continuation to pick up), rather than carrying out the
    put right away. This is going to be made a little more
    explicit by a subsequent cleanup patch. This is part of
    CVE-2013-1918 / XSA-45. (CVE-2013-1918)

  - x86: make page table unpinning preemptible ... as it may
    take significant amounts of time. Since we can't
    re-invoke the operation in a second attempt, the
    continuation logic must be slightly tweaked so that we
    make sure do_mmuext_op gets run one more time even when
    the preempted unpin operation was the last one in a
    batch. This is part of CVE-2013-1918 / XSA-45.
    (CVE-2013-1918)

  - x86: make arch_set_info_guest preemptible .. as the root
    page table validation (and the dropping of an eventual
    old one) can require meaningful amounts of time. This is
    part of CVE-2013-1918 / XSA-45. (CVE-2013-1918)

  - x86: make vcpu_reset preemptible ... as dropping the old
    page tables may take significant amounts of time. This
    is part of CVE-2013-1918 / XSA-45. (CVE-2013-1918)

  - x86: make MMUEXT_NEW_USER_BASEPTR preemptible ... as it
    may take significant amounts of time. This is part of
    CVE-2013-1918 / XSA-45. (CVE-2013-1918)

  - x86: make new_guest_cr3 preemptible ... as it may take
    significant amounts of time. This is part of
    CVE-2013-1918 / XSA-45. (CVE-2013-1918)

  - x86: make vcpu_destroy_pagetables preemptible ... as it
    may take significant amounts of time. The function,
    being moved to mm.c as the better home for it anyway,
    and to avoid having to make a new helper function there
    non-static, is given a 'preemptible' parameter
    temporarily (until, in a subsequent patch, its other
    caller is also being made capable of dealing with
    preemption). This is part of CVE-2013-1918 / XSA-45.
    (CVE-2013-1918)

  - Fix rcu domain locking for transitive grants When
    acquiring a transitive grant for copy then the owning
    domain needs to be locked down as well as the granting
    domain. This was being done, but the unlocking was not.
    The acquire code now stores the struct domain * of the
    owning domain (rather than the domid) in the active
    entry in the granting domain. The release code then does
    the unlock on the owning domain. Note that I believe I
    also fixed a bug where, for non-transitive grants the
    active entry contained a reference to the acquiring
    domain rather than the granting domain. From my reading
    of the code this would stop the release code for
    transitive grants from terminating its recursion
    correctly.

    Also, for non-transitive grants we now avoid incorrectly
    recursing in __release_grant_for_copy. This is
    CVE-2013-1964 / XSA-50. (CVE-2013-1964)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2013-May/000150.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.1", reference:"xen-4.1.2-18.el5.50")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-devel-4.1.2-18.el5.50")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-tools-4.1.2-18.el5.50")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
