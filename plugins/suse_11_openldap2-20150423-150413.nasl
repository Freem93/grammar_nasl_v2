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
  script_id(83516);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/18 13:48:31 $");

  script_cve_id("CVE-2013-4449", "CVE-2015-1545", "CVE-2015-1546");

  script_name(english:"SuSE 11.3 Security Update : openldap2 (SAT Patch Number 10635)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"openldap2 was updated to fix three security issues and one
non-security bug.

The following vulnerabilities were fixed :

  - A remote attacker could cause a denial of service (slapd
    crash) by unbinding immediately after a search request.
    (bnc#846389, CVE-2013-4449)

  - A remote attacker could cause a denial of service
    through a NULL pointer dereference and crash via an
    empty attribute list in a deref control in a search
    request. (bnc#916897, CVE-2015-1545)

  - A remote attacker could cause a denial of service
    (crash) via a crafted search query with a matched values
    control. (bnc#916914, CVE-2015-1546) The following
    non-security bug was fixed :

  - Prevent connection-0 (internal connection) from showing
    up in the monitor back-end. (bnc#905959)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=916897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=916914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4449.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1546.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10635.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:compat-libldap-2_3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libldap-2_4-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libldap-2_4-2-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"openldap2-client-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libldap-2_4-2-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"openldap2-client-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"compat-libldap-2_3-0-2.3.37-2.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libldap-2_4-2-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openldap2-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openldap2-back-meta-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openldap2-client-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libldap-2_4-2-32bit-2.4.26-0.30.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.26-0.30.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
