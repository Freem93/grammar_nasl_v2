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
  script_id(64430);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/14 15:30:09 $");

  script_cve_id("CVE-2012-2733", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534", "CVE-2012-5568", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");

  script_name(english:"SuSE 11.2 Security Update : tomcat6 (SAT Patch Number 7208)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of tomcat6 fixes the following security issues :

  - denial of service. (CVE-2012-4534)

  - tomcat: HTTP NIO connector OOM DoS via a request with
    large headers. (CVE-2012-2733)

  - tomcat: cnonce tracking weakness. (CVE-2012-5885)

  - tomcat: authentication caching weakness. (CVE-2012-5886)

  - tomcat: stale nonce weakness. (CVE-2012-5887)

  - tomcat: affected by slowloris DoS. (CVE-2012-5568)

  - tomcat: Bypass of security constraints. (CVE-2012-3546)

  - tomcat: bypass of CSRF prevention filter.
    (CVE-2012-4431)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3546.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4431.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4534.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5886.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5887.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7208.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-6.0.18-20.35.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-admin-webapps-6.0.18-20.35.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-docs-webapp-6.0.18-20.35.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-javadoc-6.0.18-20.35.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-jsp-2_1-api-6.0.18-20.35.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-lib-6.0.18-20.35.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-servlet-2_5-api-6.0.18-20.35.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"tomcat6-webapps-6.0.18-20.35.40.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
