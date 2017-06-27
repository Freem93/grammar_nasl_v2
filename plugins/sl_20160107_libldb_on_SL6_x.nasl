#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87839);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2015-3223", "CVE-2015-5330");

  script_name(english:"Scientific Linux Security Update : libldb on SL6.x, SL7.x i386/x86_64");
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
"A denial of service flaw was found in the ldb_wildcard_compare()
function of libldb. A remote attacker could send a specially crafted
packet that, when processed by an application using libldb (for
example the AD LDAP server in Samba), would cause that application to
consume an excessive amount of memory and crash. (CVE-2015-3223)

A memory-read flaw was found in the way the libldb library processed
LDB DN records with a null byte. An authenticated, remote attacker
could use this flaw to read heap-memory pages from the server.
(CVE-2015-5330)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1601&L=scientific-linux-errata&F=&S=&P=2279
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ee60793"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"ldb-tools-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-debuginfo-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libldb-devel-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"pyldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"pyldb-devel-1.1.13-3.el6_7.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ldb-tools-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-debuginfo-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libldb-devel-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pyldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pyldb-devel-1.1.20-1.el7_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
