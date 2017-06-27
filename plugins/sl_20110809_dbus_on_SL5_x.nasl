#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61107);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-2200");

  script_name(english:"Scientific Linux Security Update : dbus on SL5.x, SL6.x i386/x86_64");
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
"D-Bus is a system for sending messages between applications. It is
used for the system-wide message bus service and as a
per-user-login-session messaging facility.

A denial of service flaw was found in the way the D-Bus library
handled endianness conversion when receiving messages. A local user
could use this flaw to send a specially crafted message to dbus-daemon
or to a service using the bus, such as Avahi or NetworkManager,
possibly causing the daemon to exit or the service to disconnect from
the bus. (CVE-2011-2200)

All users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to
take effect, all running instances of dbus-daemon and all running
applications using the libdbus library must be restarted, or the
system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=1276
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?517f2d82"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"dbus-1.1.2-16.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"dbus-devel-1.1.2-16.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"dbus-libs-1.1.2-16.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"dbus-x11-1.1.2-16.el5_7")) flag++;

if (rpm_check(release:"SL6", reference:"dbus-1.2.24-5.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-devel-1.2.24-5.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-libs-1.2.24-5.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-x11-1.2.24-5.el6_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
