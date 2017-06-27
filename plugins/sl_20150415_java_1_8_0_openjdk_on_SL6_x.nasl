#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82816);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/20 14:02:08 $");

  script_cve_id("CVE-2005-1080", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0470", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL6.x, SL7.x i386/srpm/x86_64");
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
"An off-by-one flaw, leading to a buffer overflow, was found in the
font parsing code in the 2D component in OpenJDK. A specially crafted
font file could possibly cause the Java Virtual Machine to execute
arbitrary code, allowing an untrusted Java application or applet to
bypass Java sandbox restrictions. (CVE-2015-0469)

A flaw was found in the way the Hotspot component in OpenJDK handled
phantom references. An untrusted Java application or applet could use
this flaw to corrupt the Java Virtual Machine memory and, possibly,
execute arbitrary code, bypassing Java sandbox restrictions.
(CVE-2015-0460)

A flaw was found in the way the JSSE component in OpenJDK parsed X.509
certificate options. A specially crafted certificate could cause JSSE
to raise an exception, possibly causing an application using JSSE to
exit unexpectedly. (CVE-2015-0488)

Multiple flaws were discovered in the Beans and Hotspot components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2015-0477,
CVE-2015-0470)

A directory traversal flaw was found in the way the jar tool extracted
JAR archive files. A specially crafted JAR archive could cause jar to
overwrite arbitrary files writable by the user running jar when the
archive was extracted. (CVE-2005-1080, CVE-2015-0480)

It was found that the RSA implementation in the JCE component in
OpenJDK did not follow recommended practices for implementing RSA
signatures. (CVE-2015-0478)

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1504&L=scientific-linux-errata&T=0&P=1788
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6b30e23"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");
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
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-1.8.0.45-28.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.45-28.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-1.8.0.45-28.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-1.8.0.45-28.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-1.8.0.45-28.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.45-28.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.45-28.b13.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-1.8.0.45-28.b13.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-1.8.0.45-30.b13.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.45-30.b13.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
