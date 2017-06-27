#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1187 and 
# Oracle Linux Security Advisory ELSA-2011-1187 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68330);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2011-1929");
  script_bugtraq_id(47930);
  script_osvdb_id(72495);
  script_xref(name:"RHSA", value:"2011:1187");

  script_name(english:"Oracle Linux 4 / 5 / 6 : dovecot (ELSA-2011-1187)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1187 :

Updated dovecot packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Dovecot is an IMAP server for Linux, UNIX, and similar operating
systems, primarily written with security in mind.

A denial of service flaw was found in the way Dovecot handled NULL
characters in certain header names. A mail message with specially
crafted headers could cause the Dovecot child process handling the
target user's connection to crash, blocking them from downloading the
message successfully and possibly leading to the corruption of their
mailbox. (CVE-2011-1929)

Users of dovecot are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing the updated packages, the dovecot service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-August/002293.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-August/002294.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-August/002295.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/19");
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
if (rpm_check(release:"EL4", reference:"dovecot-0.99.11-10.EL4")) flag++;

if (rpm_check(release:"EL5", reference:"dovecot-1.0.7-7.el5_7.1")) flag++;

if (rpm_check(release:"EL6", reference:"dovecot-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-devel-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-mysql-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-pgsql-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-pigeonhole-2.0.9-2.el6_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-devel / dovecot-mysql / dovecot-pgsql / etc");
}
