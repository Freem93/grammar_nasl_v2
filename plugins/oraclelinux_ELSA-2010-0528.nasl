#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0528 and 
# Oracle Linux Security Advisory ELSA-2010-0528 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68061);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:49:13 $");

  script_cve_id("CVE-2009-0758", "CVE-2010-2244");
  script_bugtraq_id(33946, 41075);
  script_xref(name:"RHSA", value:"2010:0528");

  script_name(english:"Oracle Linux 5 : avahi (ELSA-2010-0528)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0528 :

Updated avahi packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Avahi is an implementation of the DNS Service Discovery and Multicast
DNS specifications for Zero Configuration Networking. It facilitates
service discovery on a local network. Avahi and Avahi-aware
applications allow you to plug your computer into a network and, with
no configuration, view other people to chat with, view printers to
print to, and find shared files on other computers.

A flaw was found in the way the Avahi daemon (avahi-daemon) processed
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

All users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, avahi-daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-July/001533.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected avahi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"avahi-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-compat-howl-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-compat-howl-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-compat-libdns_sd-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-compat-libdns_sd-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-glib-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-glib-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-qt3-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-qt3-devel-0.6.16-9.el5_5")) flag++;
if (rpm_check(release:"EL5", reference:"avahi-tools-0.6.16-9.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-compat-howl / avahi-compat-howl-devel / etc");
}
