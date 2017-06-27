#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42867);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-3616", "CVE-2009-3638", "CVE-2009-3640");

  script_name(english:"SuSE 11 Security Update : KVM (SAT Patch Number 1553)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of QEMU KVM fixes the following bugs :

  - use-after-free bug in VNC code which might be used to
    execute code on the host system injected from the guest
    system. (CVE-2009-3616: CVSS v2 Base Score: 8.5)

  - integer overflow in kvm_dev_ioctl_get_supported_cpuid().
    (CVE-2009-3638: CVSS v2 Base Score: 7.2)

  - update_cr8_intercept() NULL pointer dereference.
    (CVE-2009-3640: CVSS v2 Base Score: 2.1)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=540247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=549487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=550072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=550732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=550917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3616.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3638.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3640.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1553.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(20, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kvm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kvm-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kvm-78.0.10.6-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.37_0.1-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kvm-kmp-pae-78.2.6.30.1_2.6.27.37_0.1-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kvm-78.0.10.6-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.37_0.1-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kvm-78.0.10.6-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.37_0.1-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kvm-kmp-pae-78.2.6.30.1_2.6.27.37_0.1-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kvm-78.0.10.6-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.37_0.1-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
