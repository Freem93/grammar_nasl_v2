#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0930 and 
# Oracle Linux Security Advisory ELSA-2011-0930 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68306);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2011-2176");
  script_bugtraq_id(48396);
  script_osvdb_id(73318);
  script_xref(name:"RHSA", value:"2011:0930");

  script_name(english:"Oracle Linux 6 : NetworkManager (ELSA-2011-0930)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0930 :

Updated NetworkManager packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

NetworkManager is a network link manager that attempts to keep a wired
or wireless network connection active at all times.

It was found that NetworkManager did not properly enforce PolicyKit
settings controlling the permissions to configure wireless network
sharing. A local, unprivileged user could use this flaw to bypass
intended PolicyKit restrictions, allowing them to enable wireless
network sharing. (CVE-2011-2176)

Users of NetworkManager should upgrade to these updated packages,
which contain a backported patch to correct this issue. Running
instances of NetworkManager must be restarted ('service NetworkManager
restart') for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-July/002225.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected networkmanager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/12");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"NetworkManager-0.8.1-9.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"NetworkManager-devel-0.8.1-9.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"NetworkManager-glib-0.8.1-9.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"NetworkManager-glib-devel-0.8.1-9.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"NetworkManager-gnome-0.8.1-9.el6_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-devel / NetworkManager-glib / etc");
}
