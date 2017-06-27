#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1582 and 
# Oracle Linux Security Advisory ELSA-2013-1582 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71128);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:25:12 $");

  script_cve_id("CVE-2013-4238");
  script_bugtraq_id(61738);
  script_osvdb_id(96215);
  script_xref(name:"RHSA", value:"2013:1582");

  script_name(english:"Oracle Linux 6 : python (ELSA-2013-1582)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1582 :

Updated python packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Python is an interpreted, interactive, object-oriented programming
language.

A flaw was found in the way the Python SSL module handled X.509
certificate fields that contain a NULL byte. An attacker could
potentially exploit this flaw to conduct man-in-the-middle attacks to
spoof SSL servers. Note that to exploit this issue, an attacker would
need to obtain a carefully crafted certificate signed by an authority
that the client trusts. (CVE-2013-4238)

These updated python packages include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of python are advised to upgrade to these updated packages,
which fix these issues and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-November/003819.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/29");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"python-2.6.6-51.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-devel-2.6.6-51.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-libs-2.6.6-51.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-test-2.6.6-51.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-tools-2.6.6-51.el6")) flag++;
if (rpm_check(release:"EL6", reference:"tkinter-2.6.6-51.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-devel / python-libs / python-test / python-tools / etc");
}
