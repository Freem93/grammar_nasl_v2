#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(100048);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2017-3139");

  script_name(english:"Scientific Linux Security Update : bind on SL6.x i386/x86_64");
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
"Security Fix(es) :

  - A denial of service flaw was found in the way BIND
    handled DNSSEC validation. A remote attacker could use
    this flaw to make named exit unexpectedly with an
    assertion failure via a specially crafted DNS response.
    (CVE-2017-3139)

Note: This issue affected only the BIND versions as shipped with EL6."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1705&L=scientific-linux-errata&F=&S=&P=2507
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8d3a2fc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
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
if (rpm_check(release:"SL6", reference:"bind-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"SL6", reference:"bind-chroot-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"SL6", reference:"bind-debuginfo-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"SL6", reference:"bind-devel-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"SL6", reference:"bind-libs-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"SL6", reference:"bind-sdb-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"SL6", reference:"bind-utils-9.8.2-0.62.rc1.el6_9.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
