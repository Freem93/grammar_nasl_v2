#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0779. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54600);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-1002");
  script_bugtraq_id(46446);
  script_xref(name:"RHSA", value:"2011:0779");

  script_name(english:"RHEL 6 : avahi (RHSA-2011:0779)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated avahi packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Avahi is an implementation of the DNS Service Discovery and Multicast
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

* Previously, the avahi packages in Red Hat Enterprise Linux 6 were
not compiled with standard RPM CFLAGS; therefore, the Stack Protector
and Fortify Source protections were not enabled, and the debuginfo
packages did not contain the information required for debugging. This
update corrects this issue by using proper CFLAGS when compiling the
packages. (BZ#629954, BZ#684276)

All users are advised to upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing
the update, avahi-daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0779.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-ui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:avahi-ui-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0779";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", reference:"avahi-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"avahi-autoipd-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"avahi-autoipd-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"avahi-autoipd-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-compat-howl-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-compat-howl-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-compat-libdns_sd-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-compat-libdns_sd-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-debuginfo-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"avahi-dnsconfd-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"avahi-dnsconfd-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"avahi-dnsconfd-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-glib-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-glib-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-gobject-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-gobject-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-libs-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-qt3-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-qt3-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-qt4-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-qt4-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"avahi-tools-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"avahi-tools-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"avahi-tools-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-ui-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"avahi-ui-devel-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"avahi-ui-tools-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"avahi-ui-tools-0.6.25-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"avahi-ui-tools-0.6.25-11.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-autoipd / avahi-compat-howl / avahi-compat-howl-devel / etc");
  }
}
