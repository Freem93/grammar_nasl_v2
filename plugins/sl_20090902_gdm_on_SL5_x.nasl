#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60652);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2009-2697");

  script_name(english:"Scientific Linux Security Update : gdm on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2009-2697 gdm not built with tcp_wrappers

A flaw was found in the way the gdm package was built. The gdm package
was missing TCP wrappers support, which could result in an
administrator believing they had access restrictions enabled when they
did not. (CVE-2009-2697)

This update also fixes the following bugs :

  - the GDM Reference Manual is now included with the gdm
    packages. The gdm-docs package installs this document in
    HTML format in '/usr/share/doc/'. (BZ#196054)

  - GDM appeared in English on systems using Telugu (te_IN).
    With this update, GDM has been localized in te_IN.
    (BZ#226931)

  - the Ctrl+Alt+Backspace sequence resets the X server when
    in runlevel 5. In previous releases, however, repeated
    use of this sequence prevented GDM from starting the X
    server as part of the reset process. This was because
    GDM sometimes did not notice the X server shutdown
    properly and would subsequently fail to complete the
    reset process. This update contains an added check to
    explicitly notify GDM whenever the X server is
    terminated, ensuring that resets are executed reliably.
    (BZ#441971)

  - the 'gdm' user is now part of the 'audio' group by
    default. This enables audio support at the login screen.
    (BZ#458331)

  - the gui/modules/dwellmouselistener.c source code
    contained incorrect XInput code that prevented tablet
    devices from working properly. This update removes the
    errant code, ensuring that tablet devices work as
    expected. (BZ#473262)

  - a bug in the XOpenDevice() function prevented the X
    server from starting whenever a device defined in
    '/etc/X11/xorg.conf' was not actually plugged in. This
    update wraps XOpenDevice() in the gdk_error_trap_pop()
    and gdk_error_trap_push() functions, which resolves this
    bug. This ensures that the X server can start properly
    even when devices defined in '/etc/X11/xorg.conf' are
    not plugged in. (BZ#474588)

GDM must be restarted for this update to take effect. Rebooting
achieves this, but changing the runlevel from 5 to 3 and back to 5
also restarts GDM.

Note: setup needed to be updated for dependencies."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=1693
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84eee8fa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=196054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=226931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=441971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=458331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=473262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=474588"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdm, gdm-docs and / or setup packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"gdm-2.16.0-56.sl")) flag++;
if (rpm_check(release:"SL5", reference:"gdm-docs-2.16.0-56.sl")) flag++;
if (rpm_check(release:"SL5", reference:"setup-2.5.58-7.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
