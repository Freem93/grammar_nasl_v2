#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1023. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35181);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-2955", "CVE-2008-2957", "CVE-2008-3532");
  script_osvdb_id(47008);
  script_xref(name:"RHSA", value:"2008:1023");

  script_name(english:"RHEL 4 / 5 : pidgin (RHSA-2008:1023)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Pidgin packages that fix several security issues and bugs are
now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is a multi-protocol Internet Messaging client.

A denial-of-service flaw was found in Pidgin's MSN protocol handler.
If a remote user was able to send, and the Pidgin user accepted, a
carefully-crafted file request, it could result in Pidgin crashing.
(CVE-2008-2955)

A denial-of-service flaw was found in Pidgin's Universal Plug and Play
(UPnP) request handling. A malicious UPnP server could send a request
to Pidgin, causing it to download an excessive amount of data,
consuming all available memory or disk space. (CVE-2008-2957)

A flaw was found in the way Pidgin handled SSL certificates. The NSS
SSL implementation in Pidgin did not properly verify the authenticity
of SSL certificates. This could have resulted in users unknowingly
connecting to a malicious SSL service. (CVE-2008-3532)

In addition, this update upgrades pidgin from version 2.3.1 to version
2.5.2, with many additional stability and functionality fixes from the
Pidgin Project.

Note: the Secure Internet Live Conferencing (SILC) chat network
protocol has recently changed, affecting all versions of pidgin
shipped with Red Hat Enterprise Linux.

Pidgin cannot currently connect to the latest version of the SILC
server (1.1.14): it fails to properly exchange keys during initial
login. This update does not correct this. Red Hat Bugzilla #474212
(linked to in the References section) has more information.

Note: after the errata packages are installed, Pidgin must be
restarted for the update to take effect.

All Pidgin users should upgrade to these updated packages, which
contains Pidgin version 2.5.2 and resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3532.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=474212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-1023.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:1023";
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
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"finch-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"finch-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"finch-devel-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"finch-devel-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-devel-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-devel-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-perl-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-perl-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"libpurple-tcl-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"libpurple-tcl-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"pidgin-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"pidgin-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"pidgin-devel-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"pidgin-devel-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"pidgin-perl-2.5.2-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"pidgin-perl-2.5.2-6.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"finch-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"finch-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"finch-devel-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"finch-devel-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-devel-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-devel-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-perl-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-perl-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-tcl-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-tcl-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-devel-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-devel-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-perl-2.5.2-6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-perl-2.5.2-6.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
  }
}
