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
  script_id(55547);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:41:52 $");

  script_cve_id("CVE-2011-2464");

  script_name(english:"SuSE 11.1 Security Update : bind (SAT Patch Number 4846)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A remote Denial of Service vulnerability has been fixed in bind.
Specially crafted packets could cause bind servers (recursive as well
as authoritative) to exit."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2464.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4846.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"bind-libs-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"bind-utils-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"bind-libs-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"bind-libs-32bit-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"bind-utils-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"bind-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"bind-chrootenv-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"bind-doc-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"bind-libs-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"bind-utils-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"bind-libs-32bit-9.6ESVR4P3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"bind-libs-32bit-9.6ESVR4P3-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
