#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:221. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12328);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-0970", "CVE-2002-1151", "CVE-2002-1247", "CVE-2002-1306");
  script_osvdb_id(59566);
  script_xref(name:"RHSA", value:"2002:221");

  script_name(english:"RHEL 2.1 : kdelibs (RHSA-2002:221)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities have been found that affect various
versions of KDE. This errata provides updates for these issues.

KDE is a graphical desktop environment for workstations. A number of
vulnerabilities have been found in various versions of KDE.

The SSL capability for Konqueror in KDE 3.0.2 and earlier does not
verify the Basic Constraints for an intermediate CA-signed
certificate, which allows remote attackers to spoof the certificates
of trusted sites via a man-in-the-middle attack. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2002-0970 to this issue.

The cross-site scripting protection for Konqueror in KDE 2.2.2 and 3.0
through 3.0.3 does not properly initialize the domains on sub-frames
and sub-iframes, which can allow remote attackers to execute scripts
and steal cookies from subframes that are in other domains.
(CVE-2002-1151)

Multiple buffer overflows exist in the KDE LAN browsing
implementation; the reslisa daemon contains a buffer overflow
vulnerability which could be exploited if the reslisa binary is SUID
root. Additionally, the lisa daemon contains a vulnerability which
potentially enables any local user, as well any any remote attacker on
the LAN who is able to gain control of the LISa port (7741 by
default), to obtain root privileges. In Red Hat Linux reslisa is not
SUID root and lisa services are not automatically started.
(CVE-2002-1247, CVE-2002-1306)

Red Hat Linux Advanced Server 2.1 provides KDE version 2.2.2 and is
therefore vulnerable to these issues. This errata provides new kdelibs
and kdenetworks packages which contain patches to correct these
issues.

Please note that there is are two additional vulnerabilities that
affect KDE 2.x which are not fixed by this errata. A vulnerability in
the rlogin KIO subsystem (rlogin.protocol) of KDE 2.x 2.1 and later,
and KDE 3.x 3.0.4 and earlier, allows local and remote attackers to
execute arbitrary code via a carefully crafted URL. (CVE-2002-1281). A
similar vulnerability affects the telnet KIO subsystem
(telnet.protocol) of KDE 2.x 2.1 and later. (CVE-2002-1282)

At this time, Red Hat recommends disabling both the rlogin and telnet
KIO protocols as a workaround. To disable both protocols, execute
these commands while logged in as root :

rm /usr/share/services/rlogin.protocol rm
/usr/share/services/telnet.protocol"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1151.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1247.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1306.html"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=102977530005148
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=102977530005148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20020908-2.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20021111-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20021111-2.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-221.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-sound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdenetwork-ppp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:221";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"arts-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-devel-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-sound-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-sound-devel-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdenetwork-2.2.2-2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdenetwork-ppp-2.2.2-2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "arts / kdelibs / kdelibs-devel / kdelibs-sound / etc");
  }
}
