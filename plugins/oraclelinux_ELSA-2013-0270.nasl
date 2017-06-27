#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0270 and 
# Oracle Linux Security Advisory ELSA-2013-0270 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68731);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2012-5783");
  script_bugtraq_id(58073);
  script_xref(name:"RHSA", value:"2013:0270");

  script_name(english:"Oracle Linux 5 / 6 : jakarta-commons-httpclient (ELSA-2013-0270)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0270 :

Updated jakarta-commons-httpclient packages that fix one security
issue are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Jakarta Commons HttpClient component can be used to build
HTTP-aware client applications (such as web browsers and web service
clients).

The Jakarta Commons HttpClient component did not verify that the
server hostname matched the domain name in the subject's Common Name
(CN) or subjectAltName field in X.509 certificates. This could allow a
man-in-the-middle attacker to spoof an SSL server if they had a
certificate that was valid for any domain name. (CVE-2012-5783)

All users of jakarta-commons-httpclient are advised to upgrade to
these updated packages, which correct this issue. Applications using
the Jakarta Commons HttpClient component must be restarted for this
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003270.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jakarta-commons-httpclient packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-commons-httpclient-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-commons-httpclient-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-commons-httpclient-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"jakarta-commons-httpclient-3.0-7jpp.2")) flag++;
if (rpm_check(release:"EL5", reference:"jakarta-commons-httpclient-demo-3.0-7jpp.2")) flag++;
if (rpm_check(release:"EL5", reference:"jakarta-commons-httpclient-javadoc-3.0-7jpp.2")) flag++;
if (rpm_check(release:"EL5", reference:"jakarta-commons-httpclient-manual-3.0-7jpp.2")) flag++;

if (rpm_check(release:"EL6", reference:"jakarta-commons-httpclient-3.1-0.7.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"jakarta-commons-httpclient-demo-3.1-0.7.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"jakarta-commons-httpclient-javadoc-3.1-0.7.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"jakarta-commons-httpclient-manual-3.1-0.7.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-httpclient / jakarta-commons-httpclient-demo / etc");
}
