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
  script_id(54934);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/01/09 11:40:37 $");

  script_cve_id("CVE-2011-1146", "CVE-2011-1166", "CVE-2011-1486", "CVE-2011-1583");

  script_name(english:"SuSE 11.1 Security Update : Xen (SAT Patch Number 4491)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Collective May/2011 update for Xen

Xen :

  - 679344: Xen: multi-vCPU pv guest may crash host

  - 675817: Kernel panic when creating HVM guests on AMD
    platforms with XSAVE

  - 678871: dom0 hangs long time when starting hvm guests
    with memory >= 64GB

  - 675363: Random lockups with kernel-xen. Possibly
    graphics related

  - 678229: restore of sles HVM fails

  - 672833: xen-tools bug causing problems with Ubuntu 10.10
    under Xen 4.

  - 665610: xm console > 1 to same VM messes up both
    consoles

  - 687981: mistyping model type when defining VIF crashes
    VM

  - 688473: Fix potential buffer overflow in decode

  - 691238: revert accidental behaviour change in xm list

  - 680824: dom0 can't recognize boot disk when IOMMU is
    enabled

  - 623680: xen kernel freezes during boot when processor
    module is loaded vm-install :

  - 678152: virt-manager: harmless block device admin
    actions on FV guests mess up network (VIF) device type
    ==> network lost.

  - 688757: SLED10SP4 fully virtualized in SLES10SP4 XEN -
    kernel panic libvirt :

  - 674371: qemu aio mode per disk

  - 675861: Force FLR on for buggy SR-IOV devices

  - 678406: libvirt: several API calls do not honour
    read-only

  - 684877: libvirt: error reporting in libvirtd is not
    thread safe

  - 686737: virsh: Add option 'model' to attach-interface

  - 681546: Fix xmdomain.cfg to libvirt XML format
    conversion

  - 688306: Handle support for recent KVM versions"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=686737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=687981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=691238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1583.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4491.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:vm-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libvirt-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libvirt-doc-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libvirt-python-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"vm-install-0.4.30-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-kmp-default-4.0.1_21326_08_2.6.32.36_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-kmp-pae-4.0.1_21326_08_2.6.32.36_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-libs-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-tools-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xen-tools-domU-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libvirt-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libvirt-doc-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libvirt-python-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"vm-install-0.4.30-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.1_21326_08_2.6.32.36_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"libvirt-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"libvirt-doc-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"libvirt-python-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"vm-install-0.4.30-0.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-doc-html-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-doc-pdf-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-kmp-default-4.0.1_21326_08_2.6.32.36_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-kmp-pae-4.0.1_21326_08_2.6.32.36_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-libs-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-tools-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"xen-tools-domU-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libvirt-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libvirt-doc-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libvirt-python-0.7.6-1.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"vm-install-0.4.30-0.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-html-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-doc-pdf-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-kmp-default-4.0.1_21326_08_2.6.32.36_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-libs-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-4.0.1_21326_08-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xen-tools-domU-4.0.1_21326_08-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
