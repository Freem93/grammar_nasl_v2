#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60637);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-2414", "CVE-2009-2416");

  script_name(english:"Scientific Linux Security Update : libxml and libxml2 on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-2414 libxml, libxml2, mingw32-libxml2: Stack overflow by
parsing root XML element DTD definition

CVE-2009-2416 libxml, libxml2, mingw32-libxml2: Pointer use-after-free
flaws by parsing Notation and Enumeration attribute types

A stack overflow flaw was found in the way libxml processes the root
XML document element definition in a DTD. A remote attacker could
provide a specially crafted XML file, which once opened by a local,
unsuspecting user, would lead to denial of service (application
crash). (CVE-2009-2414)

Multiple use-after-free flaws were found in the way libxml parses the
Notation and Enumeration attribute types. A remote attacker could
provid a specially crafted XML file, which once opened by a local,
unsuspecting user, would lead to denial of service (application
crash). (CVE-2009-2416)

The desktop must be restarted (log out, then log back in) for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0908&L=scientific-linux-errata&T=0&P=314
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?432c4746"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"libxml-1.8.17-9.3")) flag++;
if (rpm_check(release:"SL3", reference:"libxml-devel-1.8.17-9.3")) flag++;
if (rpm_check(release:"SL3", reference:"libxml2-2.5.10-15")) flag++;
if (rpm_check(release:"SL3", reference:"libxml2-devel-2.5.10-15")) flag++;
if (rpm_check(release:"SL3", reference:"libxml2-python-2.5.10-15")) flag++;

if (rpm_check(release:"SL4", reference:"libxml2-2.6.16-12.7")) flag++;
if (rpm_check(release:"SL4", reference:"libxml2-devel-2.6.16-12.7")) flag++;
if (rpm_check(release:"SL4", reference:"libxml2-python-2.6.16-12.7")) flag++;

if (rpm_check(release:"SL5", reference:"libxml2-2.6.26-2.1.2.8")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-devel-2.6.26-2.1.2.8")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-python-2.6.26-2.1.2.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
