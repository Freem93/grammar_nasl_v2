#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0465 and 
# Oracle Linux Security Advisory ELSA-2011-0465 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68260);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2010-1000", "CVE-2011-1586");
  script_bugtraq_id(40141);
  script_osvdb_id(74943);
  script_xref(name:"RHSA", value:"2011:0465");

  script_name(english:"Oracle Linux 6 : kdenetwork (ELSA-2011-0465)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0465 :

Updated kdenetwork packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kdenetwork packages contain networking applications for the K
Desktop Environment (KDE).

A directory traversal flaw was found in the way KGet, a download
manager, handled the 'file' element in Metalink files. An attacker
could use this flaw to create a specially crafted Metalink file that,
when opened, would cause KGet to overwrite arbitrary files accessible
to the user running KGet. (CVE-2011-1586)

Users of kdenetwork should upgrade to these updated packages, which
contain a backported patch to resolve this issue. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002088.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdenetwork packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/22");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"kdenetwork-4.3.4-11.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"kdenetwork-devel-4.3.4-11.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"kdenetwork-libs-4.3.4-11.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdenetwork / kdenetwork-devel / kdenetwork-libs");
}
