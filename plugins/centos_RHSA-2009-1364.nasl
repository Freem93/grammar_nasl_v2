#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1364 and 
# CentOS Errata and Security Advisory 2009:1364 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43789);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-2697");
  script_osvdb_id(57657);
  script_xref(name:"RHSA", value:"2009:1364");

  script_name(english:"CentOS 5 : gdm (CESA-2009:1364)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48e13964"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd5d9bee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"gdm-2.16.0-56.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gdm-docs-2.16.0-56.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
