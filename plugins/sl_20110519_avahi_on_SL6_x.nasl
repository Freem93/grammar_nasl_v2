#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61038);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-1002");

  script_name(english:"Scientific Linux Security Update : avahi on SL6.x i386/x86_64");
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
"Avahi is an implementation of the DNS Service Discovery and Multicast
DNS specifications for Zero Configuration Networking. It facilitates
service discovery on a local network. Avahi and Avahi-aware
applications allow you to plug your computer into a network and, with
no configuration, view other people to chat with, view printers to
print to, and find shared files on other computers.

A flaw was found in the way the Avahi daemon (avahi-daemon) processed
Multicast DNS (mDNS) packets with an empty payload. An attacker on the
local network could use this flaw to cause avahi-daemon on a target
system to enter an infinite loop via an empty mDNS UDP packet.
(CVE-2011-1002)

This update also fixes the following bug :

  - Previously, the avahi packages in Scientific Linux 6
    were not compiled with standard RPM CFLAGS; therefore,
    the Stack Protector and Fortify Source protections were
    not enabled, and the debuginfo packages did not contain
    the information required for debugging. This update
    corrects this issue by using proper CFLAGS when
    compiling the packages. (BZ#629954, BZ#684276)

All users are advised to upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing
the update, avahi-daemon will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=424
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a542526c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=629954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=684276"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
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
if (rpm_check(release:"SL6", reference:"avahi-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-autoipd-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-compat-howl-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-compat-howl-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-compat-libdns_sd-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-compat-libdns_sd-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-debuginfo-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-dnsconfd-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-glib-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-glib-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-gobject-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-gobject-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-libs-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-qt3-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-qt3-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-qt4-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-qt4-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-tools-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-ui-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-ui-devel-0.6.25-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"avahi-ui-tools-0.6.25-11.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
