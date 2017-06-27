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
  script_id(50930);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/10/25 23:46:56 $");

  script_cve_id("CVE-2009-3555");

  script_name(english:"SuSE 11 Security Update : Mozilla (SAT Patch Number 2239)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla NSS was updated to version 3.12.6.

This fixes all currently known issues in mozilla-nss, and also
implements the new TLS/SSL renegotiation handling. (CVE-2009-3555)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3555.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2239.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:zlib-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libfreebl3-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-nss-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-nss-tools-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"zlib-1.2.3-106.34")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libfreebl3-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libfreebl3-32bit-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-nss-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-nss-tools-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"zlib-1.2.3-106.34")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"zlib-32bit-1.2.3-106.34")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libfreebl3-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-nss-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-nss-tools-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"zlib-1.2.3-106.34")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libfreebl3-32bit-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-nss-32bit-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"zlib-32bit-1.2.3-106.34")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libfreebl3-32bit-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.6-3.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"zlib-32bit-1.2.3-106.34")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
