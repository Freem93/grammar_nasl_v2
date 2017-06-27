#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0181. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46283);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2008-3279");
  script_osvdb_id(63523);
  script_xref(name:"RHSA", value:"2010:0181");

  script_name(english:"RHEL 5 : brltty (RHSA-2010:0181)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated brltty packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

brltty (Braille TTY) is a background process (daemon) which provides
access to the Linux console (when in text mode) for a blind person
using a refreshable braille display. It drives the braille display,
and provides complete screen review functionality.

It was discovered that a brltty library had an insecure relative RPATH
(runtime library search path) set in the ELF (Executable and Linking
Format) header. A local user able to convince another user to run an
application using brltty in an attacker-controlled directory, could
run arbitrary code with the privileges of the victim. (CVE-2008-3279)

These updated packages also provide fixes for the following bugs :

* the brltty configuration file is documented in the brltty manual
page, but there is no separate manual page for the /etc/brltty.conf
configuration file: running 'man brltty.conf' returned 'No manual
entry for brltty.conf' rather than opening the brltty manual entry.
This update adds brltty.conf.5 as an alias to the brltty manual page.
Consequently, running 'man brltty.conf' now opens the manual entry
documenting the brltty.conf specification. (BZ#530554)

* previously, the brltty-pm.conf configuration file was installed in
the /etc/brltty/ directory. This file, which configures Papenmeier
Braille Terminals for use with Red Hat Enterprise Linux, is optional.
As well, it did not come with a corresponding manual page. With this
update, the file has been moved to
/usr/share/doc/brltty-3.7.2/BrailleDrivers/Papenmeier/. This directory
also includes a README document that explains the file's purpose and
format. (BZ#530554)

* during the brltty packages installation, the message

Creating screen inspection device /dev/vcsa...done.

was presented at the console. This was inadequate, especially during
the initial install of the system. These updated packages do not send
any message to the console during installation. (BZ#529163)

* although brltty contains ELF objects, the brltty-debuginfo package
was empty. With this update, the -debuginfo package contains valid
debugging information as expected. (BZ#500545)

* the MAX_NR_CONSOLES definition was acquired by brltty by #including
linux/tty.h in Programs/api_client.c. MAX_NR_CONSOLES has since moved
to linux/vt.h but the #include in api_client.c was not updated.
Consequently, brltty could not be built from the source RPM against
the Red Hat Enterprise Linux 5 kernel. This update corrects the
#include in api_client.c to linux/vt.h and brltty now builds from
source as expected. (BZ#456247)

All brltty users are advised to upgrade to these updated packages,
which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3279.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0181.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected brlapi, brlapi-devel and / or brltty packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:brlapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:brlapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:brltty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");
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
  rhsa = "RHSA-2010:0181";
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
  if (rpm_check(release:"RHEL5", reference:"brlapi-0.4.1-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"brlapi-devel-0.4.1-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"brltty-3.7.2-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"brltty-3.7.2-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"brltty-3.7.2-4.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "brlapi / brlapi-devel / brltty");
  }
}
