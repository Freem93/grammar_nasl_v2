#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60833);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 00:00:32 $");

  script_cve_id("CVE-2010-1172");

  script_name(english:"Scientific Linux Security Update : dbus-glib on SL5.x i386/x86_64");
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
"It was discovered that dbus-glib did not enforce the 'access' flag on
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
the updated dbus-glib packages. No other applications shipped with
Scientific Linux 5 were affected.

Running instances of NetworkManager must be restarted (service
NetworkManager restart) for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=1047
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5473b5d4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
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
if (rpm_check(release:"SL5", reference:"NetworkManager-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-devel-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-glib-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-glib-devel-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"NetworkManager-gnome-0.7.0-10.el5_5.1")) flag++;
if (rpm_check(release:"SL5", reference:"dbus-glib-0.73-10.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"dbus-glib-devel-0.73-10.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
