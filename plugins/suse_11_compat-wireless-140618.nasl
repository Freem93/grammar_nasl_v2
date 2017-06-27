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
  script_id(76198);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/24 10:49:52 $");

  script_cve_id("CVE-2013-4579", "CVE-2014-2672");

  script_name(english:"SuSE 11.3 Security Update : compat-wireless, compat-wireless-debuginfo, etc (SAT Patch Number 9414)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for the compat-wireless kernel modules provides many fixes
and enhancements :

  - Fix potential crash problem in ath9k. (CVE-2014-2672,
    bnc#871148)

  - Fix improper updates of MAC addresses in ath9k_htc.
    (bnc#851426, CVE-2013-4579)

  - Fix stability issues in iwlwifi. (bnc#865475)

  - Improve support for Intel 7625 cards in iwlwifi.
    (bnc#51021) Installation notes :

New driver modules may conflict with old modules, which are
automatically loaded from the initrd file after reboot. To apply this
maintenance update correctly, the following steps need to be executed
on a SLEPOS system :

  - Rebuild image

  - Create specific scDistributionContainer with newly built
    initrd and kernel

  - Put the updated system image in it as a scPosImage
    object Alternatively, you can use a kernel parameter to
    enforce using the kernel from the system image :

  - Rebuild image

  - Set the kernel parameter FORCE_KEXEC, by adding the
    scPxeFileTemplate object under the relevant scPosImage
    object, with the scKernelParameters attribute containing
    'FORCE_KEXEC=yes'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4579.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2672.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9414.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:compat-wireless-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:compat-wireless-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:compat-wireless-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"compat-wireless-kmp-default-3.13_3.0.101_0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"compat-wireless-kmp-pae-3.13_3.0.101_0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"compat-wireless-kmp-xen-3.13_3.0.101_0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"compat-wireless-kmp-default-3.13_3.0.101_0.31-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"compat-wireless-kmp-xen-3.13_3.0.101_0.31-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
