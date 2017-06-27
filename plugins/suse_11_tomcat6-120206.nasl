#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57855);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:56:04 $");

  script_cve_id("CVE-2011-1184", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064");

  script_name(english:"SuSE 11.1 Security Update : tomcat6 (SAT Patch Number 5759)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a regression in parameter passing (in urldecoding of
parameters that contain spaces).

In addition, multiple weaknesses in HTTP DIGESTS have been fixed
(CVE-2011-1184) :

  - The HTTP Digest Access Authentication implementation in
    Apache Tomcat 5.5.x before 5.5.34, 6.x before 6.0.33 and
    7.x before 7.0.12 does not check qop values, which might
    allow remote attackers to bypass intended
    integrity-protection requirements via a qop=auth value,
    a different vulnerability than CVE-2011-1184.
    (CVE-2011-5062)

  - The HTTP Digest Access Authentication implementation in
    Apache Tomcat 5.5.x before 5.5.34, 6.x before 6.0.33,
    and 7.x before 7.0.12 does not check realm values, which
    might allow remote attackers to bypass intended access
    restrictions by leveraging the availability of a
    protection space with weaker authentication or
    authorization requirements, a different vulnerability
    than CVE-2011-1184. (CVE-2011-5063)

  - DigestAuthenticator.java in the HTTP Digest Access
    Authentication implementation in Apache Tomcat 5.5.x
    before 5.5.34, 6.x before 6.0.33, and 7.x before 7.0.12
    uses Catalina as the hard-coded server secret (aka
    private key), which makes it easier for remote attackers
    to bypass cryptographic protection mechanisms by
    leveraging knowledge of this string, a different
    vulnerability than CVE-2011-1184. (CVE-2011-5064)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-5062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-5063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-5064.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5759.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-jsp-2_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-servlet-2_5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-6.0.18-20.35.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-admin-webapps-6.0.18-20.35.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-docs-webapp-6.0.18-20.35.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-javadoc-6.0.18-20.35.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-jsp-2_1-api-6.0.18-20.35.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-lib-6.0.18-20.35.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-servlet-2_5-api-6.0.18-20.35.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"tomcat6-webapps-6.0.18-20.35.36.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
