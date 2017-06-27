#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0616. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48313);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-1172");
  script_osvdb_id(67026);
  script_xref(name:"RHSA", value:"2010:0616");

  script_name(english:"RHEL 5 : dbus-glib (RHSA-2010:0616)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dbus-glib packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

dbus-glib is an add-on library to integrate the standard D-Bus library
with the GLib main loop and threading model. NetworkManager is a
network link manager that attempts to keep a wired or wireless network
connection active at all times.

It was discovered that dbus-glib did not enforce the 'access' flag on
exported GObject properties. If such a property were read/write
internally but specified as read-only externally, a malicious, local
user could use this flaw to modify that property of an application.
Such a change could impact the application's behavior (for example, if
an IP address were changed the network may not come up properly after
reboot) and possibly lead to a denial of service. (CVE-2010-1172)

Due to the way dbus-glib translates an application's XML definitions
of service interfaces and properties into C code at application build
time, applications built against dbus-glib that use read-only
properties needed to be rebuilt to fully fix the flaw. As such, this
update provides NetworkManager packages that have been rebuilt against
the updated dbus-glib packages. No other applications shipped with Red
Hat Enterprise Linux 5 were affected.

All dbus-glib and NetworkManager users are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue. Running instances of NetworkManager must be restarted (service
NetworkManager restart) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0616.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dbus-glib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0616";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"NetworkManager-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"NetworkManager-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"NetworkManager-devel-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"NetworkManager-devel-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"NetworkManager-glib-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"NetworkManager-glib-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"NetworkManager-glib-devel-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"NetworkManager-glib-devel-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"NetworkManager-gnome-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"NetworkManager-gnome-0.7.0-10.el5_5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"dbus-glib-0.73-10.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"dbus-glib-devel-0.73-10.el5_5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-devel / NetworkManager-glib / etc");
  }
}
