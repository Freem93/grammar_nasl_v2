#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0506. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64757);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-1182");
  script_bugtraq_id(52973);
  script_xref(name:"RHSA", value:"2013:0506");

  script_name(english:"RHEL 6 : samba4 (RHSA-2013:0506)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba4 packages that fix one security issue, multiple bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A flaw was found in the Samba suite's Perl-based DCE/RPC IDL (PIDL)
compiler, used to generate code to handle RPC calls. This could result
in code generated by the PIDL compiler to not sufficiently protect
against buffer overflows. (CVE-2012-1182)

The samba4 packages have been upgraded to upstream version 4.0.0,
which provides a number of bug fixes and enhancements over the
previous version. In particular, improved interoperability with Active
Directory (AD) domains. SSSD now uses the libndr-krb5pac library to
parse the Privilege Attribute Certificate (PAC) issued by an AD Key
Distribution Center (KDC).

The Cross Realm Kerberos Trust functionality provided by Identity
Management, which relies on the capabilities of the samba4 client
library, is included as a Technology Preview. This functionality and
server libraries, is included as a Technology Preview. This
functionality uses the libndr-nbt library to prepare Connection-less
Lightweight Directory Access Protocol (CLDAP) messages.

Additionally, various improvements have been made to the Local
Security Authority (LSA) and Net Logon services to allow verification
of trust from a Windows system. Because the Cross Realm Kerberos Trust
functionality is considered a Technology Preview, selected samba4
components are considered to be a Technology Preview. For more
information on which Samba packages are considered a Technology
Preview, refer to Table 5.1, 'Samba4 Package Support' in the Release
Notes, linked to from the References. (BZ#766333, BZ#882188)

This update also fixes the following bug :

* Prior to this update, if the Active Directory (AD) server was
rebooted, Winbind sometimes failed to reconnect when requested by
'wbinfo -n' or 'wbinfo -s' commands. Consequently, looking up users
using the wbinfo tool failed. This update applies upstream patches to
fix this problem and now looking up a Security Identifier (SID) for a
username, or a username for a given SID, works as expected after a
domain controller is rebooted. (BZ#878564)

All users of samba4 are advised to upgrade to these updated packages,
which fix these issues and add these enhancements.

Warning: If you upgrade from Red Hat Enterprise Linux 6.3 to Red Hat
Enterprise Linux 6.4 and you have Samba in use, you should make sure
that you uninstall the package named 'samba4' to avoid conflicts
during the upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1182.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faae67f0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0506.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?879a0985"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0506";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-client-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-client-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-client-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-common-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-common-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-common-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-libs-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-libs-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-libs-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-debuginfo-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-debuginfo-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-debuginfo-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-devel-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-devel-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-devel-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-libs-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-libs-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-libs-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-pidl-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-pidl-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-pidl-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-python-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-python-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-python-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-swat-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-swat-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-swat-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-test-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-test-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-test-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-clients-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-clients-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-clients-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-krb5-locator-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-krb5-locator-4.0.0-55.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-krb5-locator-4.0.0-55.el6.rc4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
  }
}
