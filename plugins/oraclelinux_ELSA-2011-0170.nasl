#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0170 and 
# Oracle Linux Security Advisory ELSA-2011-0170 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68185);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2011-0002");
  script_bugtraq_id(45791);
  script_osvdb_id(70421);
  script_xref(name:"RHSA", value:"2011:0170");

  script_name(english:"Oracle Linux 4 / 5 / 6 : libuser (ELSA-2011-0170)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0170 :

Updated libuser packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libuser library implements a standardized interface for
manipulating and administering user and group accounts. Sample
applications that are modeled after applications from the shadow
password suite (shadow-utils) are included in these packages.

It was discovered that libuser did not set the password entry
correctly when creating LDAP (Lightweight Directory Access Protocol)
users. If an administrator did not assign a password to an LDAP based
user account, either at account creation with luseradd, or with
lpasswd after account creation, an attacker could use this flaw to log
into that account with a default password string that should have been
rejected. (CVE-2011-0002)

Note: LDAP administrators that have used libuser tools to add users
should check existing user accounts for plain text passwords, and
reset them as necessary.

Users of libuser should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-January/001790.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-January/001799.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuser packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuser-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"libuser-0.52.5-1.1.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"libuser-devel-0.52.5-1.1.el4_8.1")) flag++;

if (rpm_check(release:"EL5", reference:"libuser-0.54.7-2.1.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"libuser-devel-0.54.7-2.1.el5_5.2")) flag++;

if (rpm_check(release:"EL6", reference:"libuser-0.56.13-4.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"libuser-devel-0.56.13-4.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"libuser-python-0.56.13-4.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libuser / libuser-devel / libuser-python");
}
