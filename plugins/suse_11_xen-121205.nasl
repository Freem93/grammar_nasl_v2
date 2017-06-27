#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64232);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515");

  script_name(english:"SuSE 11.2 Security Update : Xen (SAT Patch Number 7133)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues in xen :

  - Grant table version switch list corruption vulnerability
    (XSA-26). (CVE-2012-5510)

  - Several HVM operations do not validate the range of
    their inputs (XSA-27). (CVE-2012-5511)

  - HVMOP_get_mem_access crash / HVMOP_set_mem_access
    information leak (XSA-28). (CVE-2012-5512)

  - XENMEM_exchange may overwrite hypervisor memory
    (XSA-29). (CVE-2012-5513)

  - Missing unlock in
    guest_physmap_mark_populate_on_demand() (XSA-30).
    (CVE-2012-5514)

  - Several memory hypercall operations allow invalid extent
    order values (XSA-31) Also the following bugs have been
    fixed and upstream patches have been applied:.
    (CVE-2012-5515)

  - FATAL PAGE FAULT in hypervisor (arch_do_domctl)

  - 25931-x86-domctl-iomem-mapping-checks.patch

  - 26132-tmem-save-NULL-check.patch

  - 26134-x86-shadow-invlpg-check.patch

  - 26148-vcpu-timer-overflow.patch (Replaces
    CVE-2012-4535-xsa20.patch)

  - 26149-x86-p2m-physmap-error-path.patch (Replaces
    CVE-2012-4537-xsa22.patch)

  - 26150-x86-shadow-unhook-toplevel-check.patch (Replaces
    CVE-2012-4538-xsa23.patch)

  - 26151-gnttab-compat-get-status-frames.patch (Replaces
    CVE-2012-4539-xsa24.patch)

  - efi files missing in latest XEN update. (bnc#792476)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4535.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5514.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5515.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7133.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.3_06_3.0.51_0.7.9-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.3_06_3.0.51_0.7.9-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.3_06_3.0.51_0.7.9-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.3_06_3.0.51_0.7.9-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.3_06-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.3_06-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
