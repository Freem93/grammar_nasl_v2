#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1440. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70488);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/11/08 02:22:00 $");

  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5775", "CVE-2013-5776", "CVE-2013-5777", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5787", "CVE-2013-5788", "CVE-2013-5789", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5810", "CVE-2013-5812", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5818", "CVE-2013-5819", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5824", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5831", "CVE-2013-5832", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5843", "CVE-2013-5844", "CVE-2013-5846", "CVE-2013-5848", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851", "CVE-2013-5852", "CVE-2013-5854");
  script_bugtraq_id(61310, 63079, 63082, 63089, 63095, 63098, 63101, 63102, 63103, 63106, 63110, 63111, 63115, 63118, 63120, 63121, 63124, 63126, 63127, 63128, 63129, 63131, 63132, 63133, 63134, 63135, 63136, 63137, 63139, 63140, 63141, 63142, 63143, 63144, 63145, 63146, 63147, 63148, 63149, 63150, 63151, 63152, 63153, 63154, 63155, 63156, 63157, 63158);
  script_osvdb_id(95418, 98524, 98525, 98526, 98527, 98528, 98529, 98530, 98531, 98532, 98533, 98534, 98535, 98536, 98539, 98540, 98541, 98542, 98543, 98544, 98545, 98546, 98547, 98548, 98549, 98550, 98551, 98552, 98553, 98554, 98555, 98556, 98557, 98558, 98559, 98560, 98561, 98562, 98563, 98564, 98565, 98566, 98567, 98568, 98569, 98570, 98571, 98572, 98573);
  script_xref(name:"RHSA", value:"2013:1440");

  script_name(english:"RHEL 5 / 6 : java-1.7.0-oracle (RHSA-2013:1440)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-oracle packages that fix several security issues
are now available for Red Hat Enterprise Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Oracle Java SE version 7 includes the Oracle Java Runtime Environment
and the Oracle Java Software Development Kit.

This update fixes several vulnerabilities in the Oracle Java Runtime
Environment and the Oracle Java Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch Update Advisory page, listed in the References section.
(CVE-2013-3829, CVE-2013-4002, CVE-2013-5772, CVE-2013-5774,
CVE-2013-5775, CVE-2013-5776, CVE-2013-5777, CVE-2013-5778,
CVE-2013-5780, CVE-2013-5782, CVE-2013-5783, CVE-2013-5784,
CVE-2013-5787, CVE-2013-5788, CVE-2013-5789, CVE-2013-5790,
CVE-2013-5797, CVE-2013-5800, CVE-2013-5801, CVE-2013-5802,
CVE-2013-5803, CVE-2013-5804, CVE-2013-5809, CVE-2013-5810,
CVE-2013-5812, CVE-2013-5814, CVE-2013-5817, CVE-2013-5818,
CVE-2013-5819, CVE-2013-5820, CVE-2013-5823, CVE-2013-5824,
CVE-2013-5825, CVE-2013-5829, CVE-2013-5830, CVE-2013-5831,
CVE-2013-5832, CVE-2013-5838, CVE-2013-5840, CVE-2013-5842,
CVE-2013-5843, CVE-2013-5844, CVE-2013-5846, CVE-2013-5848,
CVE-2013-5849, CVE-2013-5850, CVE-2013-5851, CVE-2013-5852,
CVE-2013-5854)

All users of java-1.7.0-oracle are advised to upgrade to these updated
packages, which provide Oracle Java 7 Update 45 and resolve these
issues. All running instances of Oracle Java must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-3829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5778.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5784.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5787.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5790.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5804.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5810.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5814.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5820.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5824.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5825.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5832.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5846.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5850.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5854.html"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac29c174"
  );
  # http://www.oracle.com/technetwork/java/javase/7u45-relnotes-2016950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c8fe88a"
  );
  # http://www.oracle.com/technetwork/java/javase/7u40-relnotes-2004172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f6e7bee"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1440.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-javafx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-devel-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-javafx-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-jdbc-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-plugin-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-src-1.7.0.45-1jpp.1.el5_10")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.45-1jpp.1.el5_10")) flag++;


if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-javafx-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-jdbc-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-plugin-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-src-1.7.0.45-1jpp.2.el6_4")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.45-1jpp.2.el6_4")) flag++;



if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-oracle / java-1.7.0-oracle-devel / etc");
}
