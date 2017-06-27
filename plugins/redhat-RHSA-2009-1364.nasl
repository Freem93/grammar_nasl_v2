#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1364. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40840);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-2697");
  script_osvdb_id(57657);
  script_xref(name:"RHSA", value:"2009:1364");

  script_name(english:"RHEL 5 : gdm (RHSA-2009:1364)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdm packages that fix a security issue and several bugs are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The GNOME Display Manager (GDM) is a configurable re-implementation of
XDM, the X Display Manager. GDM allows you to log in to your system
with the X Window System running, and supports running several
different X sessions on your local machine at the same time.

A flaw was found in the way the gdm package was built. The gdm package
was missing TCP wrappers support, which could result in an
administrator believing they had access restrictions enabled when they
did not. (CVE-2009-2697)

This update also fixes the following bugs :

* the GDM Reference Manual is now included with the gdm packages. The
gdm-docs package installs this document in HTML format in
'/usr/share/doc/'. (BZ#196054)

* GDM appeared in English on systems using Telugu (te_IN). With this
update, GDM has been localized in te_IN. (BZ#226931)

* the Ctrl+Alt+Backspace sequence resets the X server when in runlevel
5. In previous releases, however, repeated use of this sequence
prevented GDM from starting the X server as part of the reset process.
This was because GDM sometimes did not notice the X server shutdown
properly and would subsequently fail to complete the reset process.
This update contains an added check to explicitly notify GDM whenever
the X server is terminated, ensuring that resets are executed
reliably. (BZ#441971)

* the 'gdm' user is now part of the 'audio' group by default. This
enables audio support at the login screen. (BZ#458331)

* the gui/modules/dwellmouselistener.c source code contained incorrect
XInput code that prevented tablet devices from working properly. This
update removes the errant code, ensuring that tablet devices work as
expected. (BZ#473262)

* a bug in the XOpenDevice() function prevented the X server from
starting whenever a device defined in '/etc/X11/xorg.conf' was not
actually plugged in. This update wraps XOpenDevice() in the
gdk_error_trap_pop() and gdk_error_trap_push() functions, which
resolves this bug. This ensures that the X server can start properly
even when devices defined in '/etc/X11/xorg.conf' are not plugged in.
(BZ#474588)

All users should upgrade to these updated packages, which resolve
these issues. GDM must be restarted for this update to take effect.
Rebooting achieves this, but changing the runlevel from 5 to 3 and
back to 5 also restarts GDM."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2697.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1364.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdm and / or gdm-docs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2009:1364";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gdm-2.16.0-56.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gdm-2.16.0-56.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gdm-2.16.0-56.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gdm-docs-2.16.0-56.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gdm-docs-2.16.0-56.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gdm-docs-2.16.0-56.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-docs");
  }
}
