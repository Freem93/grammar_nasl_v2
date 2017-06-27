#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64962);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/07 11:50:57 $");

  script_cve_id("CVE-2013-0292");

  script_name(english:"Scientific Linux Security Update : dbus-glib on SL5.x, SL6.x i386/x86_64");
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
"A flaw was found in the way dbus-glib filtered the message sender
(message source subject) when the 'NameOwnerChanged' signal was
received. This could trick a system service using dbus-glib (such as
fprintd) into believing a signal was sent from a privileged process,
when it was not. A local attacker could use this flaw to escalate
their privileges. (CVE-2013-0292)

All running applications linked against dbus-glib, such as fprintd and
NetworkManager, must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=5781
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db01e966"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected dbus-glib, dbus-glib-debuginfo and / or
dbus-glib-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"dbus-glib-0.73-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"dbus-glib-debuginfo-0.73-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"dbus-glib-devel-0.73-11.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"dbus-glib-0.86-6.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-glib-debuginfo-0.86-6.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-glib-devel-0.86-6.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
