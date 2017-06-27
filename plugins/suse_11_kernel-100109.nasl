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
  script_id(52685);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-3080", "CVE-2009-3939", "CVE-2009-4005", "CVE-2009-4020", "CVE-2009-4138", "CVE-2009-4307", "CVE-2009-4308", "CVE-2009-4536", "CVE-2009-4538");

  script_name(english:"SuSE 11 Security Update : Linux kernel (SAT Patch Number 1753)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Indications Everyone using the Linux Kernel on s390x architecture
should update.

Contraindications None.

Problem description

The SUSE Linux Enterprise 11 Kernel was updated to 2.6.27.42 fixing
various bugs and security issues.

The following security issues were fixed :

  - A underflow in the e1000 jumbo ethernet frame handling
    could be use by link-local remote attackers to crash the
    machine or potentially execute code in kernel context.
    This requires the attacker to be able to send Jumbo
    Frames to the target machine. (CVE-2009-4536)

  - A underflow in the e1000e jumbo ethernet frame handling
    could be use by link-local remote attackers to crash the
    machine or potentially execute code in kernel context.
    This requires the attacker to be able to send Jumbo
    Frames to the target machine. (CVE-2009-4538)

  - drivers/firewire/ohci.c in the Linux kernel, when
    packet-per-buffer mode is used, allows local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unknown other impact via
    an unspecified ioctl associated with receiving an ISO
    packet that contains zero in the payload-length field.
    (CVE-2009-4138)

  - The ext4_fill_flex_info function in fs/ext4/super.c in
    the Linux kernel allows user-assisted remote attackers
    to cause a denial of service (divide-by-zero error and
    panic) via a malformed ext4 filesystem containing a
    super block with a large FLEX_BG group size (aka
    s_log_groups_per_flex value). (CVE-2009-4307)

  - The ext4_decode_error function in fs/ext4/super.c in the
    ext4 filesystem in the Linux kernel before 2.6.32 allows
    user-assisted remote attackers to cause a denial of
    service (NULL pointer dereference), and possibly have
    unspecified other impact, via a crafted read-only
    filesystem that lacks a journal. (CVE-2009-4308)

  - The poll_mode_io file for the megaraid_sas driver in the
    Linux kernel has world-writable permissions, which
    allows local users to change the I/O mode of the driver
    by modifying this file. (CVE-2009-3939)

  - The collect_rx_frame function in
    drivers/isdn/hisax/hfc_usb.c in the Linux kernel allows
    attackers to have an unspecified impact via a crafted
    HDLC packet that arrives over ISDN and triggers a buffer
    under-read. (CVE-2009-4005)

  - A negative offset in a ioctl in the GDTH RAID driver was
    fixed. (CVE-2009-3080)

  - Stack-based buffer overflow in the hfs subsystem in the
    Linux kernel allows remote attackers to have an
    unspecified impact via a crafted Hierarchical File
    System (HFS) filesystem, related to the hfs_readdir
    function in fs/hfs/dir.c. (CVE-2009-4020)

For a complete list of changes, please look at the RPM changelog.

Solution

Please install the updates provided at the location noted below.

Installation notes

This update is provided as a set of RPM packages that can easily be
installed onto a running system by using the YaST online update
module."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=490030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=515645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=523487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=526819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=528811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=544763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=545367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=546449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=549567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=560055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=561621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=565267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=566480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3939.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4308.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4538.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1753.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"ext4dev-kmp-default-0_2.6.27.42_0.1-7.1.24")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-default-2.6.27.42-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-default-base-2.6.27.42-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-default-man-2.6.27.42-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-source-2.6.27.42-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"kernel-syms-2.6.27.42-0.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
