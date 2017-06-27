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
  script_id(50914);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2010-0743", "CVE-2010-2221");

  script_name(english:"SuSE 11 Security Update : iSCSI (SAT Patch Number 2878)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of iscscitarget/tgt fixes multiple overflows and a format
string vulnerability :

  - CVE-2010-2221: CVSS v2 Base Score: 5.0 (MEDIUM)
    (AV:N/AC:L/Au:N/C:N/I:N/A:P): Buffer Errors (CWE-119)

  - CVE-2010-0743: CVSS v2 Base Score: 5.0 (MEDIUM)
    (AV:N/AC:L/Au:N/C:N/I:N/A:P): Format String
    Vulnerability (CWE-134)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2221.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2878.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:iscsitarget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:iscsitarget-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:iscsitarget-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:iscsitarget-kmp-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:iscsitarget-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:0, reference:"iscsitarget-0.4.15-94.14.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"iscsitarget-kmp-default-0.4.15_2.6.27.48_0.6-94.14.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"iscsitarget-kmp-pae-0.4.15_2.6.27.48_0.6-94.14.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"iscsitarget-kmp-vmi-0.4.15_2.6.27.48_0.6-94.14.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"iscsitarget-kmp-xen-0.4.15_2.6.27.48_0.6-94.14.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"iscsitarget-kmp-xen-0.4.15_2.6.27.48_0.6-94.14.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
