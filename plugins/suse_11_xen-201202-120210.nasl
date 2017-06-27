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
  script_id(58396);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2012-0029");

  script_name(english:"SuSE 11.1 Security Update : Xen and libvirt (SAT Patch Number 5796)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This collective update 2012/02 for Xen provides fixes for the
following reports :

Xen :

  - 740165: Fix heap overflow in e1000 device emulation
    (applicable to Xen qemu - CVE-2012-0029)

  - 739585: Xen block-attach fails after repeated
    attach/detach

  - 727515: Fragmented packets hang network boot of HVM
    guest

  - 736824: Microcode patches for AMD's 15h processors panic
    the system

  - 732782: xm create hangs when maxmen value is enclosed in
    'quotes'

  - 734826: xm rename doesn't work anymore

  - 694863: kexec fails in xen

  - 726332: Fix considerable performance hit by previous
    changeset

  - 649209: Fix slow Xen live migrations libvirt

  - 735403: Fix connection with virt-manager as normal user
    virt-utils

  - Add Support for creating images that can be run on
    Microsoft Hyper-V host (Fix vpc file format. Add support
    for fixed disks)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=725169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0029.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5796.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:virt-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libvirt-0.7.6-1.29.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libvirt-doc-0.7.6-1.29.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libvirt-python-0.7.6-1.29.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"virt-utils-1.1.3-1.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_02_2.6.32.54_0.3-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libvirt-0.7.6-1.29.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libvirt-doc-0.7.6-1.29.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libvirt-python-0.7.6-1.29.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"virt-utils-1.1.3-1.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-html-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-pdf-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.3_21548_02_2.6.32.54_0.3-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-kmp-trace-4.0.3_21548_02_2.6.32.54_0.3-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.3_21548_02-0.5.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.3_21548_02-0.5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
