#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99577);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5461");

  script_name(english:"Scientific Linux Security Update : nss and nss-util on SL6.x, SL7.x i386/x86_64");
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
"The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version:
nss (3.28.4), nss-util (3.28.4).

Security Fix(es) :

  - An out-of-bounds write flaw was found in the way NSS
    performed certain Base64-decoding operations. An
    attacker could use this flaw to create a specially
    crafted certificate which, when parsed by NSS, could
    cause it to crash or execute arbitrary code, using the
    permissions of the user running an application compiled
    against the NSS library. (CVE-2017-5461)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=19015
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef98a059"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"nss-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.28.4-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.28.4-1.el6_9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-debuginfo-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-devel-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-sysinit-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-tools-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-debuginfo-3.28.4-1.0.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-devel-3.28.4-1.0.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
