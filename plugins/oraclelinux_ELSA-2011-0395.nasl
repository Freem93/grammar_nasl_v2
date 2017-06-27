#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0395 and 
# Oracle Linux Security Advisory ELSA-2011-0395 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68241);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2011-0727");
  script_bugtraq_id(47063);
  script_osvdb_id(72551);
  script_xref(name:"RHSA", value:"2011:0395");

  script_name(english:"Oracle Linux 6 : gdm (ELSA-2011-0395)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0395 :

Updated gdm packages that fix one security issue are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The GNOME Display Manager (GDM) provides the graphical login screen,
shown shortly after boot up, log out, and when user-switching.

A race condition flaw was found in the way GDM handled the cache
directories used to store users' dmrc and face icon files. A local
attacker could use this flaw to trick GDM into changing the ownership
of an arbitrary file via a symbolic link attack, allowing them to
escalate their privileges. (CVE-2011-0727)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for reporting this issue.

All users should upgrade to these updated packages, which contain a
backported patch to correct this issue. GDM must be restarted for this
update to take effect. Rebooting achieves this, but changing the
runlevel from 5 to 3 and back to 5 also restarts GDM."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-March/002040.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm-plugin-fingerprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm-plugin-smartcard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm-user-switch-applet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/29");
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
if (rpm_check(release:"EL6", reference:"gdm-2.30.4-21.0.2.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"gdm-libs-2.30.4-21.0.2.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"gdm-plugin-fingerprint-2.30.4-21.0.2.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"gdm-plugin-smartcard-2.30.4-21.0.2.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"gdm-user-switch-applet-2.30.4-21.0.2.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-libs / gdm-plugin-fingerprint / gdm-plugin-smartcard / etc");
}
