#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1151. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61454);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-2668");
  script_bugtraq_id(53823);
  script_osvdb_id(83078);
  script_xref(name:"RHSA", value:"2012:1151");

  script_name(english:"RHEL 6 : openldap (RHSA-2012:1151)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

It was found that the OpenLDAP server daemon ignored olcTLSCipherSuite
settings. This resulted in the default cipher suite always being used,
which could lead to weaker than expected ciphers being accepted during
Transport Layer Security (TLS) negotiation with OpenLDAP clients.
(CVE-2012-2668)

This update also fixes the following bug :

* When the smbk5pwd overlay was enabled in an OpenLDAP server, and a
user changed their password, the Microsoft NT LAN Manager (NTLM) and
Microsoft LAN Manager (LM) hashes were not computed correctly. This
led to the sambaLMPassword and sambaNTPassword attributes being
updated with incorrect values, preventing the user logging in using a
Windows-based client or a Samba client.

With this update, the smbk5pwd overlay is linked against OpenSSL. As
such, the NTLM and LM hashes are computed correctly, and password
changes work as expected when using smbk5pwd. (BZ#844428)

Users of OpenLDAP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the OpenLDAP daemons will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2668.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1151.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1151";
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
  if (rpm_check(release:"RHEL6", reference:"openldap-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-clients-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-clients-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-clients-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openldap-debuginfo-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openldap-devel-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-servers-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-servers-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-servers-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-servers-sql-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-servers-sql-2.4.23-26.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-servers-sql-2.4.23-26.el6_3.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-debuginfo / openldap-devel / etc");
  }
}
