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
  script_id(70758);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/11/07 14:21:05 $");

  script_cve_id("CVE-2013-4419");

  script_name(english:"SuSE 11.3 Security Update : guestfs (SAT Patch Number 8465)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A predictable socketname in the guestfish commandline tool could be
used by a local attacker to gain access to guestfish sessions of other
users on the same system. (CVE-2013-4419)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4419.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8465.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:guestfs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:guestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:guestfsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libguestfs0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/05");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"guestfs-data-1.20.4-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"guestfs-tools-1.20.4-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"guestfsd-1.20.4-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"libguestfs0-1.20.4-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"guestfs-data-1.20.4-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"guestfs-tools-1.20.4-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"guestfsd-1.20.4-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libguestfs0-1.20.4-0.18.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
