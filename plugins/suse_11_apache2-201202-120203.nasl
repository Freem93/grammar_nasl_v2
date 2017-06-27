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
  script_id(58030);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2007-6750", "CVE-2012-0031", "CVE-2012-0053");

  script_name(english:"SuSE 11.1 Security Update : Apache2 (SAT Patch Number 5760)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of apache2 and libapr1 fixes regressions and several
security problems.

  - Fixed a scoreboard corruption (shared mem segment) by
    child causes crash of privileged parent (invalid free())
    during shutdown. (CVE-2012-0031)

  - Fixed an issue in error responses that could expose
    'httpOnly' cookies when no custom ErrorDocument is
    specified for status code 400'. (CVE-2012-0053)

  - The 'mod_reqtimeout' module was backported from Apache
    2.2.21 to help mitigate the 'Slowloris' Denial of
    Service attack. You need to enable the 'mod_reqtimeout'
    module in your existing apache configuration to make it
    effective, e.g. in the APACHE_MODULES line in
    /etc/sysconfig/apache2. For more detailed information,
    check also the README file. (CVE-2007-6750)

Also the following bugs have been fixed :

  - Fixed init script action 'check-reload' to avoid
    potential crashes. (bnc#728876)

  - An overlapping memcpy() was replaced by memmove() to
    make this work with newer glibcs. (bnc#738067 /
    bnc#741874)

  - libapr1: reset errno to zero to not return previous
    value despite good status of new operation. (bnc#739783)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6750.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0053.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5760.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libapr1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-2.2.12-1.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-doc-2.2.12-1.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-example-pages-2.2.12-1.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-prefork-2.2.12-1.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-utils-2.2.12-1.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"apache2-worker-2.2.12-1.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libapr1-1.3.3-11.18.19.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
