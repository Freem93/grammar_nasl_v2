#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0757. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66029);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/10 18:05:24 $");

  script_cve_id("CVE-2013-0401", "CVE-2013-0402", "CVE-2013-1488", "CVE-2013-1491", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1561", "CVE-2013-1563", "CVE-2013-1564", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2414", "CVE-2013-2415", "CVE-2013-2416", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2423", "CVE-2013-2424", "CVE-2013-2425", "CVE-2013-2426", "CVE-2013-2427", "CVE-2013-2428", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2434", "CVE-2013-2435", "CVE-2013-2436", "CVE-2013-2438", "CVE-2013-2439", "CVE-2013-2440");
  script_bugtraq_id(58397, 58493, 58504, 58507, 59088, 59089, 59124, 59128, 59131, 59137, 59141, 59145, 59149, 59153, 59154, 59159, 59162, 59165, 59166, 59167, 59170, 59172, 59175, 59178, 59179, 59184, 59185, 59187, 59190, 59191, 59194, 59195, 59203, 59206, 59208, 59212, 59213, 59219, 59220, 59228, 59234, 59243);
  script_osvdb_id(91204, 91205, 91206, 91472, 92335, 92336, 92337, 92338, 92339, 92340, 92341, 92342, 92343, 92344, 92345, 92346, 92347, 92348, 92349, 92350, 92351, 92352, 92353, 92354, 92355, 92356, 92357, 92358, 92359, 92360, 92361, 92362, 92363, 92364, 92365, 92366, 92367, 92368, 92369, 92370, 92371, 92372);
  script_xref(name:"RHSA", value:"2013:0757");

  script_name(english:"RHEL 5 / 6 : java-1.7.0-oracle (RHSA-2013:0757)");
  script_summary(english:"Checks rpm output for the updated packages");

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
(CVE-2013-0401, CVE-2013-0402, CVE-2013-1488, CVE-2013-1491,
CVE-2013-1518, CVE-2013-1537, CVE-2013-1540, CVE-2013-1557,
CVE-2013-1558, CVE-2013-1561, CVE-2013-1563, CVE-2013-1564,
CVE-2013-1569, CVE-2013-2383, CVE-2013-2384, CVE-2013-2394,
CVE-2013-2414, CVE-2013-2415, CVE-2013-2416, CVE-2013-2417,
CVE-2013-2418, CVE-2013-2419, CVE-2013-2420, CVE-2013-2421,
CVE-2013-2422, CVE-2013-2423, CVE-2013-2424, CVE-2013-2425,
CVE-2013-2426, CVE-2013-2427, CVE-2013-2428, CVE-2013-2429,
CVE-2013-2430, CVE-2013-2431, CVE-2013-2432, CVE-2013-2433,
CVE-2013-2434, CVE-2013-2435, CVE-2013-2436, CVE-2013-2438,
CVE-2013-2439, CVE-2013-2440)

All users of java-1.7.0-oracle are advised to upgrade to these updated
packages, which provide Oracle Java 7 Update 21 and resolve these
issues. All running instances of Oracle Java must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1561.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1564.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2394.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2414.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2431.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2436.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2440.html"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpuapr2013-1928497.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b0871bd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0757.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Reflection Type Confusion Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-devel-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-javafx-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-jdbc-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-plugin-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.7.0-oracle-src-1.7.0.21-1jpp.1.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.21-1jpp.1.el5")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-javafx-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-jdbc-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-plugin-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-src-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.21-1jpp.1.el6")) flag++;

if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"java-1.7.0-oracle-javafx-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"java-1.7.0-oracle-jdbc-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"java-1.7.0-oracle-plugin-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"java-1.7.0-oracle-src-1.7.0.21-1jpp.1.el6")) flag++;
if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.21-1jpp.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
