#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0104.
#

include("compat.inc");

if (description)
{
  script_id(93397);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2016-7092", "CVE-2016-7094");
  script_osvdb_id(143907, 143909);
  script_xref(name:"IAVB", value:"2016-B-0140");

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2016-0104)");
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

  - From: Andrew Cooper Subject: x86/shadow: Avoid
    overflowing sh_ctxt->seg_reg[] hvm_get_seg_reg does not
    perform a range check on its input segment, calls
    hvm_get_segment_register and writes straight into
    sh_ctxt->seg_reg[]. x86_seg_none is outside the bounds
    of sh_ctxt->seg_reg[], and will hit a BUG in
    [vmx,svm]_get_segment_register. HVM guests running with
    shadow paging can end up performing a virtual to linear
    translation with x86_seg_none. This is used for
    addresses which are already linear. However, none of
    this is a legitimate pagetable update, so fail the
    emulation in such a case. This is XSA-187
    (CVE-2016-7094)

  - x86/32on64: don't allow recursive page tables from L3 L3
    entries are special in PAE mode, and hence can't
    reasonably be used for setting up recursive (and hence
    linear) page table mappings. Since abuse is possible
    when the guest in fact gets run on 4-level page tables,
    this needs to be excluded explicitly. This is XSA-185.

    Conflict: xen/arch/x86/mm.c (CVE-2016-7092)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-September/000519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26ce459d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.223.36")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.223.36")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.223.36")) flag++;

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
