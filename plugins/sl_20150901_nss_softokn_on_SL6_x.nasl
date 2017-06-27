#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85759);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/03 13:42:47 $");

  script_cve_id("CVE-2015-2730");

  script_name(english:"Scientific Linux Security Update : nss-softokn on SL6.x, SL7.x i386/x86_64");
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
"A flaw was found in the way NSS verified certain ECDSA (Elliptic Curve
Digital Signature Algorithm) signatures. Under certain conditions, an
attacker could use this flaw to conduct signature forgery attacks.
(CVE-2015-2730)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1509&L=scientific-linux-errata&F=&S=&P=5841
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c39e4dc8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"nss-softokn-3.14.3-23.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-debuginfo-3.14.3-23.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-devel-3.14.3-23.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-freebl-3.14.3-23.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-freebl-devel-3.14.3-23.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-3.16.2.3-13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-debuginfo-3.16.2.3-13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-devel-3.16.2.3-13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-3.16.2.3-13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.16.2.3-13.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
