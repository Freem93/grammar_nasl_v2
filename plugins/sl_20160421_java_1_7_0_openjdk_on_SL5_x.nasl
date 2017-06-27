#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(90673);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3427");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL5.x, SL7.x i386/x86_64");
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

  - Multiple flaws were discovered in the Serialization and
    Hotspot components in OpenJDK. An untrusted Java
    application or applet could use these flaws to
    completely bypass Java sandbox restrictions.
    (CVE-2016-0686, CVE-2016-0687)

  - It was discovered that the RMI server implementation in
    the JMX component in OpenJDK did not restrict which
    classes can be deserialized when deserializing
    authentication credentials. A remote, unauthenticated
    attacker able to connect to a JMX port could possibly
    use this flaw to trigger deserialization flaws.
    (CVE-2016-3427)

  - It was discovered that the JAXP component in OpenJDK
    failed to properly handle Unicode surrogate pairs used
    as part of the XML attribute values. Specially crafted
    XML input could cause a Java application to use an
    excessive amount of memory when parsed. (CVE-2016-3425)

  - It was discovered that the Security component in OpenJDK
    failed to check the digest algorithm strength when
    generating DSA signatures. The use of a digest weaker
    than the key strength could lead to the generation of
    signatures that were weaker than expected.
    (CVE-2016-0695)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1604&L=scientific-linux-errata&F=&S=&P=13345
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2001bf38"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");
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
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-1.7.0.101-2.6.6.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.101-2.6.6.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-demo-1.7.0.101-2.6.6.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-devel-1.7.0.101-2.6.6.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.101-2.6.6.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-src-1.7.0.101-2.6.6.1.el5_11")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.101-2.6.6.1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.101-2.6.6.1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.101-2.6.6.1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.101-2.6.6.1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.101-2.6.6.1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.101-2.6.6.1.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.7.0-openjdk-javadoc-1.7.0.101-2.6.6.1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.101-2.6.6.1.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
