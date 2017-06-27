#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60699);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:08 $");

  script_cve_id("CVE-2009-2625");

  script_name(english:"Scientific Linux Security Update : xerces-j2 on SL5.x i386/x86_64");
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
"CVE-2009-2625 OpenJDK: XML parsing Denial-Of-Service (6845701)

A flaw was found in the way the Apache Xerces2 Java Parser processed
the SYSTEM identifier in DTDs. A remote attacker could provide a
specially crafted XML file, which once parsed by an application using
the Apache Xerces2 Java Parser, would lead to a denial of service
(application hang due to excessive CPU use). (CVE-2009-2625)

Applications using the Apache Xerces2 Java Parser must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0912&L=scientific-linux-errata&T=0&P=197
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c616b180"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"xerces-j2-2.7.1-7jpp.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"xerces-j2-demo-2.7.1-7jpp.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"xerces-j2-javadoc-apis-2.7.1-7jpp.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"xerces-j2-javadoc-impl-2.7.1-7jpp.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"xerces-j2-javadoc-other-2.7.1-7jpp.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"xerces-j2-javadoc-xni-2.7.1-7jpp.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"xerces-j2-scripts-2.7.1-7jpp.2.el5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
