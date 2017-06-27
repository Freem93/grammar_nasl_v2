#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2387-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87670);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-8370");
  script_osvdb_id(131484);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : grub2 (SUSE-SU-2015:2387-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix buffer overflows when reading username and password.
    (bsc#956631, CVE-2015-8370)

  - Check MS-DOS header to find PE file header. (bsc#954126)

  - Use dirname for copying Xen kernel and initrd to esp.
    (bsc#955493)

  - Fix reading password by grub2-mkpasswd-pbdk2 without
    controlling tty. (bsc#954519)

  - Add luks, gcry_rijndael and gcry_sha1 to signed EFI
    image to support LUKS partition in default setup.
    (bsc#917427, bsc#955609)

  - Expand list of grub.cfg search path in PV Xen guests for
    systems installed on btrfs snapshots. (bsc#946148,
    bsc#952539)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/774666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8370.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152387-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b311d5f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2015-1027=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2015-1027=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-i386-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-s390x-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-x86_64-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-x86_64-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"grub2-i386-pc-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"grub2-x86_64-efi-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"grub2-x86_64-xen-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"grub2-debugsource-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"grub2-s390x-emu-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"grub2-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"grub2-debuginfo-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"grub2-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"grub2-debuginfo-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"grub2-i386-pc-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"grub2-x86_64-efi-2.02~beta2-73.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"grub2-x86_64-xen-2.02~beta2-73.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2");
}
