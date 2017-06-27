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
  script_id(58263);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/02/06 11:43:19 $");

  script_cve_id("CVE-2011-2725");

  script_name(english:"SuSE 11.1 Security Update : ark (SAT Patch Number 5906)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ark was prone to a path traversal vulnerability allowing a
maliciously-crafted zip file to allow for an arbitrary file to be
displayed and, if the user has appropriate credentials, removed.
(CVE-2011-2725)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2725.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5906.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kcharselect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdessh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kfloppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kgpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ktimer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kwalletmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kwikdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:okteta");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"ark-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kcalc-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kdessh-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kdf-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kfloppy-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kgpg-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kwalletmanager-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kwikdisk-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"okteta-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"ark-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kcalc-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kdessh-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kdf-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kfloppy-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kgpg-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kwalletmanager-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kwikdisk-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"okteta-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ark-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kcalc-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kcharselect-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kdessh-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kdf-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kfloppy-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kgpg-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ktimer-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kwalletmanager-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kwikdisk-4.3.5-0.3.3")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"okteta-4.3.5-0.3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
