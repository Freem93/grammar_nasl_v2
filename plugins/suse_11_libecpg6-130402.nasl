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
  script_id(65829);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/13 15:30:41 $");

  script_cve_id("CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901");

  script_name(english:"SuSE 11.2 Security Update : PostgreSQL (SAT Patch Number 7585)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to version 9.1.9 fixes :

  - Fix insecure parsing of server command-line switches.
    (CVE-2013-1899)

  - Reset OpenSSL randomness state in each postmaster child
    process. (CVE-2013-1900)

  - Make REPLICATION privilege checks test current user not
    authenticated user. (CVE-2013-1901)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1899.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1900.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1901.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7585.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/07");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libecpg6-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libpq5-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"postgresql91-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libecpg6-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libpq5-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libpq5-32bit-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"postgresql91-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libecpg6-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libpq5-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"postgresql91-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"postgresql91-contrib-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"postgresql91-docs-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"postgresql91-server-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libpq5-32bit-9.1.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libpq5-32bit-9.1.9-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
