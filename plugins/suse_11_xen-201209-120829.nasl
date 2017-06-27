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
  script_id(64236);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3498", "CVE-2012-3515");

  script_name(english:"SuSE 11.2 Security Update : Xen (SAT Patch Number 6748)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN was updated 4.1.3 to fix multiple bugs and security issues.

The following security issues have been fixed :

  - xen: hypercall set_debugreg vulnerability (XSA-12).
    (CVE-2012-3494)

  - xen: hypercall physdev_get_free_pirq vulnerability
    (XSA-13). (CVE-2012-3495)

  - xen: XENMEM_populate_physmap DoS vulnerability (XSA-14).
    (CVE-2012-3496)

  - xen: PHYSDEVOP_map_pirq index vulnerability (XSA-16).
    (CVE-2012-3498)

  - xen: Qemu VT100 emulation vulnerability (XSA-17) Also
    the following bugs have been fixed:. (CVE-2012-3515)

  - pvscsi support of attaching Luns - (bnc#776995) The
    following related bugs in vm-install 0.5.12 have been
    fixed :

  - vm-install does not pass --extra-args in --upgrade.
    (bnc#776300)

  - Add for support Open Enterprise Server 11

  - Add support for Windows 8 and Windows Server 2012

  - Add support for Ubuntu 12 (Precise Pangolin)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3515.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6748.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:vm-install");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/29");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"vm-install-0.5.12-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.3_02_3.0.38_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.3_02_3.0.38_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"vm-install-0.5.12-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.3_02_3.0.38_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.3_02_3.0.38_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.3_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.3_02-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
