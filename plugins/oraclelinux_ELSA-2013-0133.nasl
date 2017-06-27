#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0133 and 
# Oracle Linux Security Advisory ELSA-2013-0133 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68704);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2011-2722");
  script_bugtraq_id(45833, 48892);
  script_osvdb_id(76797);
  script_xref(name:"RHSA", value:"2013:0133");

  script_name(english:"Oracle Linux 5 : hplip3 (ELSA-2013-0133)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0133 :

Updated hplip3 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers
for Hewlett-Packard (HP) printers and multifunction peripherals.

It was found that the HP CUPS (Common UNIX Printing System) fax filter
in HPLIP created a temporary file in an insecure way. A local attacker
could use this flaw to perform a symbolic link attack, overwriting
arbitrary files accessible to a process using the fax filter (such as
the hp3-sendfax tool). (CVE-2011-2722)

This update also fixes the following bug :

* Previous modifications of the hplip3 package to allow it to be
installed alongside the original hplip package introduced several
problems to fax support; for example, the hp-sendfax utility could
become unresponsive. These problems have been fixed with this update.
(BZ#501834)

All users of hplip3 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003203.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hpijs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsane-hpaio3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"hpijs3-3.9.8-15.el5")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-3.9.8-15.el5")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-common-3.9.8-15.el5")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-gui-3.9.8-15.el5")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-libs-3.9.8-15.el5")) flag++;
if (rpm_check(release:"EL5", reference:"libsane-hpaio3-3.9.8-15.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs3 / hplip3 / hplip3-common / hplip3-gui / hplip3-libs / etc");
}
