#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1220. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56000);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:02:23 $");

  script_cve_id("CVE-2010-0547", "CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694", "CVE-2011-2724");
  script_osvdb_id(74871);
  script_xref(name:"RHSA", value:"2011:1220");

  script_name(english:"RHEL 5 : samba3x (RHSA-2011:1220)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba3x packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A cross-site scripting (XSS) flaw was found in the password change
page of the Samba Web Administration Tool (SWAT). If a remote attacker
could trick a user, who was logged into the SWAT interface, into
visiting a specially crafted URL, it would lead to arbitrary web
script execution in the context of the user's SWAT session.
(CVE-2011-2694)

It was found that SWAT web pages did not protect against Cross-Site
Request Forgery (CSRF) attacks. If a remote attacker could trick a
user, who was logged into the SWAT interface, into visiting a
specially crafted URL, the attacker could perform Samba configuration
changes with the privileges of the logged in user. (CVE-2011-2522)

It was found that the fix for CVE-2010-0547, provided by the Samba
rebase in RHBA-2011:0054, was incomplete. The mount.cifs tool did not
properly handle share or directory names containing a newline
character, allowing a local attacker to corrupt the mtab (mounted file
systems table) file via a specially crafted CIFS (Common Internet File
System) share mount request, if mount.cifs had the setuid bit set.
(CVE-2011-2724)

It was found that the mount.cifs tool did not handle certain errors
correctly when updating the mtab file. If mount.cifs had the setuid
bit set, a local attacker could corrupt the mtab file by setting a
small file size limit before running mount.cifs. (CVE-2011-1678)

Note: mount.cifs from the samba3x packages distributed by Red Hat does
not have the setuid bit set. We recommend that administrators do not
manually set the setuid bit for mount.cifs.

Red Hat would like to thank the Samba project for reporting
CVE-2011-2694 and CVE-2011-2522, and Dan Rosenberg for reporting
CVE-2011-1678. Upstream acknowledges Nobuhiro Tsuji of NTT DATA
Security Corporation as the original reporter of CVE-2011-2694, and
Yoshihiro Ishikawa of LAC Co., Ltd. as the original reporter of
CVE-2011-2522.

Users of Samba are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the smb service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1678.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2522.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2694.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2724.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1220.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1220";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-client-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-client-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-client-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-common-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-common-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-common-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-doc-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-doc-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-doc-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-domainjoin-gui-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-domainjoin-gui-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-domainjoin-gui-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-swat-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-swat-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-swat-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-3.5.4-0.83.el5_7.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-devel-3.5.4-0.83.el5_7.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba3x / samba3x-client / samba3x-common / samba3x-doc / etc");
  }
}
