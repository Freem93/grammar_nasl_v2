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
  script_id(51199);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2008-4776", "CVE-2010-1000");

  script_name(english:"SuSE 11 / 11.1 Security Update : kdenetwork (SAT Patch Numbers 3563 / 3564)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of kdenetwork fixes several bugs, the security related
issues are :

  - The 'name' attribute of the 'file' element of metalink
    files is not properly sanitised this can be exploited to
    download files to arbitrary directories. (CVE-2010-1000:
    CVSS v2 Base Score: 4.3 (AV:N/AC:M/Au:N/C:N/I:P/A:N):
    CWE-22)

  - The included libgadu version allowed remote servers to
    cause a denial of service (crash) via a buffer
    over-read. (CVE-2008-4776: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): CWE-119)

Non-security issues :

  - kopete: ICQ login broken; login server changed.
    (bnc#653852)

  - kopete cant connect to yahoo. (bnc#516347)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=516347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=525528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=604709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-4776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1000.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3563 / 3564 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdenetwork4-filesharing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/16");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kde4-kget-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kde4-knewsticker-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kde4-kopete-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kde4-kppp-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kde4-krdc-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kde4-krfb-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kdenetwork4-filesharing-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kde4-kget-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kde4-knewsticker-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kde4-kopete-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kde4-kppp-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kde4-krdc-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kde4-krfb-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kdenetwork4-filesharing-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kdenetwork4-filesharing-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kget-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kopete-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kppp-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"krdc-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"krfb-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kdenetwork4-filesharing-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kget-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kopete-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kppp-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"krdc-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"krfb-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kde4-kget-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kde4-knewsticker-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kde4-kopete-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kde4-krdc-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kde4-krfb-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"kdenetwork4-filesharing-4.1.3-7.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kdenetwork4-filesharing-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kget-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kopete-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"krdc-4.3.5-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"krfb-4.3.5-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
