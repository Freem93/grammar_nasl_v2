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
  script_id(50925);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2010-2798", "CVE-2010-2803", "CVE-2010-2942", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-3015", "CVE-2010-3078", "CVE-2010-3080", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3310");

  script_name(english:"SuSE 11 Security Update : Linux kernel (SAT Patch Numbers 3358 / 3361 / 3362)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update of the SUSE Linux Enterprise 11 GA kernel updates
the kernel to 2.6.27.54 and fixes various security issues and other
bugs.

The following security issues were fixed :

  - Multiple integer signedness errors in net/rose/af_rose.c
    in the Linux kernel allowed local users to cause a
    denial of service (heap memory corruption) or possibly
    have unspecified other impact via a rose_getname
    function call, related to the rose_bind and rose_connect
    functions. (CVE-2010-3310)

  - A kernel information leak via the WEXT ioctl was fixed.
    (CVE-2010-2955)

  - A double free in an alsa error path was fixed, which
    could lead to kernel crashes. (CVE-2010-3080)

  - Fixed a kernel information leak in the xfs filesystem.
    (CVE-2010-3078)

  - Fixed a kernel information leak in the cxgb3 driver.
    (CVE-2010-3296)

  - Fixed a kernel information leak in the net/eql driver.
    (CVE-2010-3297)

  - The irda_bind function in net/irda/af_irda.c in the
    Linux kernel did not properly handle failure of the
    irda_open_tsap function, which allowed local users to
    cause a denial of service (NULL pointer dereference and
    panic) and possibly have unspecified other impact via
    multiple unsuccessful calls to bind on an AF_IRDA (aka
    PF_IRDA) socket. (CVE-2010-2954)

  - The 'os2' xattr namespace on the jfs filesystem could be
    used to bypass xattr namespace rules. (CVE-2010-2946)

  - Fixed a kernel information leak in the net scheduler
    code. (CVE-2010-2942)

  - Integer overflow in the ext4_ext_get_blocks function in
    fs/ext4/extents.c in the Linux kernel allowed local
    users to cause a denial of service (BUG and system
    crash) via a write operation on the last block of a
    large file, followed by a sync operation.
    (CVE-2010-3015)

  - The drm_ioctl function in drivers/gpu/drm/drm_drv.c in
    the Direct Rendering Manager (DRM) subsystem in the
    Linux kernel allowed local users to obtain potentially
    sensitive information from kernel memory by requesting a
    large memory-allocation amount. (CVE-2010-2803)

  - The gfs2_dirent_find_space function in fs/gfs2/dir.c in
    the Linux kernel used an incorrect size value in
    calculations associated with sentinel directory entries,
    which allowed local users to cause a denial of service
    (NULL pointer dereference and panic) and possibly have
    unspecified other impact by renaming a file in a GFS2
    filesystem, related to the gfs2_rename function in
    fs/gfs2/ops_inode.c. (CVE-2010-2798)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=472432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=524981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=536699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=577967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=598293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=601283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=608994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=613273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=616080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=627386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=627447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=628604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=631801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=635413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=635425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=640660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=640721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2942.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2946.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2954.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3297.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3310.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3358 / 3361 / 3362 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:iscsitarget-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:oracleasm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-default-extra-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-pae-extra-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-source-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-syms-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kernel-xen-extra-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-default-extra-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kernel-xen-extra-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"ext4dev-kmp-default-0_2.6.27.54_0.2-7.1.43")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-default-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-default-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-source-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kernel-syms-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.27.54_0.2-7.1.43")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-vmi-0_2.6.27.54_0.2-7.1.43")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.27.54_0.2-7.1.43")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-pae-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-pae-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-vmi-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-vmi-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-xen-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kernel-xen-base-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"iscsitarget-kmp-default-0.4.15_2.6.27.54_0.2-94.14.8")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-default-man-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"oracleasm-kmp-default-2.0.5_2.6.27.54_0.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.27.54_0.2-7.1.43")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.27.54-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kernel-xen-base-2.6.27.54-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
