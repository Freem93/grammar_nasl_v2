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
  script_id(50911);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:46:54 $");

  script_cve_id("CVE-2009-3289");

  script_name(english:"SuSE 11 Security Update : glib2 (SAT Patch Number 1831)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When copying symbolic links the g_file_copy function set the target of
the link to mode 0777 therefore exposing potentially sensitive
information or allowing other user to modify files they should not
have access to (CVE-2009-3289). This has been fixed.

This update also fixes a problem where glib2 couldn't access remote
URLs when run outside of a GNOME session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=500520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=538005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3289.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1831.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glib2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgio-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgio-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libglib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libglib-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgmodule-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgobject-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgthread-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/19");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"glib2-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"glib2-devel-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"glib2-lang-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libgio-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libgio-fam-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libglib-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libgmodule-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libgobject-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libgthread-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"glib2-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"glib2-devel-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"glib2-lang-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgio-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgio-fam-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libglib-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgmodule-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgobject-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgthread-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"glib2-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"glib2-doc-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"glib2-lang-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libgio-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libglib-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libgmodule-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libgobject-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libgthread-2_0-0-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libgio-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libglib-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libgmodule-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libgobject-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libgthread-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.18.2-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.18.2-7.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
