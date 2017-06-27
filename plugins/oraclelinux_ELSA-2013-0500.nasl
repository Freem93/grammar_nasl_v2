#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0500 and 
# Oracle Linux Security Advisory ELSA-2013-0500 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68741);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2011-2722", "CVE-2013-0200");
  script_bugtraq_id(48892, 58079);
  script_xref(name:"RHSA", value:"2013:0500");

  script_name(english:"Oracle Linux 6 : hplip (ELSA-2013-0500)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0500 :

Updated hplip packages that fix several security issues, multiple
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The hplip packages contain the Hewlett-Packard Linux Imaging and
Printing Project (HPLIP), which provides drivers for Hewlett-Packard
printers and multi-function peripherals.

Several temporary file handling flaws were found in HPLIP. A local
attacker could use these flaws to perform a symbolic link attack,
overwriting arbitrary files accessible to a process using HPLIP.
(CVE-2013-0200, CVE-2011-2722)

The CVE-2013-0200 issues were discovered by Tim Waugh of Red Hat.

The hplip packages have been upgraded to upstream version 3.12.4,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#731900)

This update also fixes the following bugs :

* Previously, the hpijs package required the obsolete cupsddk-drivers
package, which was provided by the cups package. Under certain
circumstances, this dependency caused hpijs installation to fail. This
bug has been fixed and hpijs no longer requires cupsddk-drivers.
(BZ#829453)

* The configuration of the Scanner Access Now Easy (SANE) back end is
located in the /etc/sane.d/dll.d/ directory, however, the hp-check
utility checked only the /etc/sane.d/dll.conf file. Consequently,
hp-check checked for correct installation, but incorrectly reported a
problem with the way the SANE back end was installed. With this
update, hp-check properly checks for installation problems in both
locations as expected. (BZ#683007)

All users of hplip are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003293.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
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
if (rpm_check(release:"EL6", reference:"hpijs-3.12.4-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-3.12.4-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-common-3.12.4-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-gui-3.12.4-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-libs-3.12.4-4.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libsane-hpaio-3.12.4-4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hplip / hplip-common / hplip-gui / hplip-libs / etc");
}
