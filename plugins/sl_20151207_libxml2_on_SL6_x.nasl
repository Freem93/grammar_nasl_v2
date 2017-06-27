#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87235);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/17 15:21:31 $");

  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");

  script_name(english:"Scientific Linux Security Update : libxml2 on SL6.x i386/x86_64");
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
"Several denial of service flaws were found in libxml2, a library
providing support for reading, modifying, and writing XML and HTML
files. A remote attacker could provide a specially crafted XML or HTML
file that, when processed by an application using libxml2, would cause
that application to use an excessive amount of CPU, leak potentially
sensitive information, or in certain cases crash the application.
(CVE-2015-5312, CVE-2015-7497, CVE-2015-7498, CVE-2015-7499,
CVE-2015-7500 CVE-2015-7941, CVE-2015-7942, CVE-2015-8241,
CVE-2015-8242, CVE-2015-8317, BZ#1213957, BZ#1281955)

The desktop must be restarted (log out, then log back in) for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcb55eec"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1213957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1281955"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");
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
if (rpm_check(release:"SL6", reference:"libxml2-2.7.6-20.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-debuginfo-2.7.6-20.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-devel-2.7.6-20.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-python-2.7.6-20.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libxml2-static-2.7.6-20.el6_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
