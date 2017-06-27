#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(86750);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");

  script_name(english:"Scientific Linux Security Update : nss, nss-util, and nspr on SL6.x, SL7.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-poison flaw and a heap-based buffer overflow flaw were
found in the way NSS parsed certain ASN.1 structures. An attacker
could use these flaws to cause NSS to crash or execute arbitrary code
with the permissions of the user running an application compiled
against the NSS library. (CVE-2015-7181, CVE-2015-7182)

A heap-based buffer overflow was found in NSPR. An attacker could use
this flaw to cause NSPR to crash or execute arbitrary code with the
permissions of the user running an application compiled against the
NSPR library. (CVE-2015-7183)

Note: Applications using NSPR's PL_ARENA_ALLOCATE, PR_ARENA_ALLOCATE,
PL_ARENA_GROW, or PR_ARENA_GROW macros need to be rebuild against the
fixed nspr packages to completely resolve the CVE-2015-7183 issue.
This erratum includes nss and nss-utils packages rebuilt against the
fixed nspr version."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1511&L=scientific-linux-errata&F=&S=&P=1275
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c2a406d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"nspr-4.10.8-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-debuginfo-4.10.8-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-devel-4.10.8-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-3.19.1-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.19.1-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.19.1-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.19.1-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.19.1-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.19.1-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.19.1-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.19.1-2.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.19.1-2.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-4.10.8-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-debuginfo-4.10.8-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-devel-4.10.8-2.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-3.19.1-7.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-debuginfo-3.19.1-7.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-devel-3.19.1-7.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.19.1-7.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-sysinit-3.19.1-7.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-tools-3.19.1-7.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-3.19.1-4.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-debuginfo-3.19.1-4.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-devel-3.19.1-4.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
