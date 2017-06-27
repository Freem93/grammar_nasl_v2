#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95833);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/15 14:46:41 $");

  script_cve_id("CVE-2016-0764");

  script_name(english:"Scientific Linux Security Update : NetworkManager on SL7.x x86_64");
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
"The following packages have been upgraded to a newer upstream version:
NetworkManager (1.4.0), NetworkManager-libreswan (1.2.4),
network-manager- applet (1.4.0), libnl3 (3.2.28).

Security Fix(es) :

  - A race condition vulnerability was discovered in
    NetworkManager. Temporary files were created insecurely
    when saving or updating connection settings, which could
    allow local users to read connection secrets such as VPN
    passwords or WiFi keys. (CVE-2016-0764)

Additional Changes :"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=11489
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1eaed8cb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-adsl-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-bluetooth-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-config-server-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-debuginfo-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", reference:"NetworkManager-dispatcher-routing-rules-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-glib-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-glib-devel-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libnm-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libnm-devel-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libreswan-1.2.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libreswan-debuginfo-1.2.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-libreswan-gnome-1.2.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-team-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-tui-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-wifi-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"NetworkManager-wwan-1.4.0-12.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnl3-3.2.28-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnl3-cli-3.2.28-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnl3-debuginfo-3.2.28-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnl3-devel-3.2.28-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnl3-doc-3.2.28-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnm-gtk-1.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnm-gtk-devel-1.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnma-1.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libnma-devel-1.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"network-manager-applet-1.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"network-manager-applet-debuginfo-1.4.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nm-connection-editor-1.4.0-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
