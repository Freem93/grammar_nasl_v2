#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0528. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47874);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2009-0758", "CVE-2010-2244");
  script_bugtraq_id(33946, 41075);
  script_xref(name:"RHSA", value:"2010:0528");

  script_name(english:"RHEL 5 : avahi (RHSA-2010:0528)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated avahi packages that fix two security issues are now available
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
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0528.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/28");
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
  rhsa = "RHSA-2010:0528";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL5", reference:"avahi-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-compat-howl-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-compat-howl-devel-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-compat-libdns_sd-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-compat-libdns_sd-devel-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-devel-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-glib-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-glib-devel-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-qt3-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"avahi-qt3-devel-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"avahi-tools-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"avahi-tools-0.6.16-9.el5_5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"avahi-tools-0.6.16-9.el5_5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-compat-howl / avahi-compat-howl-devel / etc");
  }
}
