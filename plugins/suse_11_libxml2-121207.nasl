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
  script_id(64206);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/26 05:42:54 $");

  script_cve_id("CVE-2012-5134");

  script_name(english:"SuSE 11.2 Security Update : libxml2 (SAT Patch Number 7140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer underflow in the entity decoding of libxml2 could
have caused a Denial of Service or potentially allowed the execution
of arbitrary code. This has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5134.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7140.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libxml2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libxml2-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libxml2-python-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libxml2-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libxml2-python-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libxml2-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libxml2-doc-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libxml2-python-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.21.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
