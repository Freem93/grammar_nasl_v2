#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60814);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2009-0758", "CVE-2010-2244");

  script_name(english:"Scientific Linux Security Update : avahi on SL5.x i386/x86_64");
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
"A flaw was found in the way the Avahi daemon (avahi-daemon) processed
Multicast DNS (mDNS) packets with corrupted checksums. An attacker on
the local network could use this flaw to cause avahi-daemon on a
target system to exit unexpectedly via specially crafted mDNS packets.
(CVE-2010-2244)

A flaw was found in the way avahi-daemon processed incoming unicast
mDNS messages. If the mDNS reflector were enabled on a system, an
attacker on the local network could send a specially crafted unicast
mDNS message to that system, resulting in its avahi-daemon flooding
the network with a multicast packet storm, and consuming a large
amount of CPU. Note: The mDNS reflector is disabled by default.
(CVE-2009-0758)

After installing the update, avahi-daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=1275
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?246fe06c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
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
if (rpm_check(release:"SL5", reference:"avahi-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-compat-howl-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-compat-howl-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-compat-libdns_sd-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-compat-libdns_sd-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-glib-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-glib-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-qt3-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-qt3-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"avahi-tools-0.6.16-9.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
