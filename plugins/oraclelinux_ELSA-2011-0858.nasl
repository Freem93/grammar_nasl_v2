#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0858 and 
# Oracle Linux Security Advisory ELSA-2011-0858 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68288);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 19:01:50 $");

  script_cve_id("CVE-2009-2625");
  script_bugtraq_id(35958);
  script_osvdb_id(56984);
  script_xref(name:"RHSA", value:"2011:0858");

  script_name(english:"Oracle Linux 6 : xerces-j2 (ELSA-2011-0858)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0858 :

Updated xerces-j2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The xerces-j2 packages provide the Apache Xerces2 Java Parser, a
high-performance XML parser. A Document Type Definition (DTD) defines
the legal syntax (and also which elements can be used) for certain
types of files, such as XML files.

A flaw was found in the way the Apache Xerces2 Java Parser processed
the SYSTEM identifier in DTDs. A remote attacker could provide a
specially crafted XML file, which once parsed by an application using
the Apache Xerces2 Java Parser, would lead to a denial of service
(application hang due to excessive CPU use). (CVE-2009-2625)

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. Applications using the Apache
Xerces2 Java Parser must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-June/002178.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-j2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"xerces-j2-2.7.1-12.6.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"xerces-j2-demo-2.7.1-12.6.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"xerces-j2-javadoc-apis-2.7.1-12.6.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"xerces-j2-javadoc-impl-2.7.1-12.6.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"xerces-j2-javadoc-other-2.7.1-12.6.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"xerces-j2-javadoc-xni-2.7.1-12.6.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"xerces-j2-scripts-2.7.1-12.6.el6_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-j2 / xerces-j2-demo / xerces-j2-javadoc-apis / etc");
}
