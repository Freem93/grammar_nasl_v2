#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1543. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71003);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-4124");
  script_bugtraq_id(61597);
  script_osvdb_id(95969);
  script_xref(name:"RHSA", value:"2013:1543");

  script_name(english:"RHEL 6 : samba4 (RHSA-2013:1543)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba4 packages that fix one security issue and two bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

An integer overflow flaw was found in the way Samba handled an
Extended Attribute (EA) list provided by a client. A malicious client
could send a specially crafted EA list that triggered an overflow,
causing the server to loop and reprocess the list using an excessive
amount of memory. (CVE-2013-4124)

Note: This issue did not affect the default configuration of the Samba
server.

This update fixes the following bugs :

* When Samba was installed in the build root directory, the RPM target
might not have existed. Consequently, the find-debuginfo.sh script did
not create symbolic links for the libwbclient.so.debug module
associated with the target. With this update, the paths to the
symbolic links are relative so that the symbolic links are now created
correctly. (BZ#882338)

* Previously, the samba4 packages were missing a dependency for the
libreplace.so module which could lead to installation failures. With
this update, the missing dependency has been added to the dependency
list of the samba4 packages and installation now proceeds as expected.
(BZ#911264)

All samba4 users are advised to upgrade to these updated packages,
which contain a backported patch to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4124.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1543.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
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
  rhsa = "RHSA-2013:1543";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-client-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-client-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-client-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-common-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-common-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-common-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-libs-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-libs-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-libs-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-debuginfo-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-debuginfo-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-debuginfo-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-devel-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-devel-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-devel-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-libs-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-libs-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-libs-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-pidl-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-pidl-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-pidl-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-python-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-python-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-python-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-swat-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-swat-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-swat-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-test-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-test-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-test-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-clients-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-clients-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-clients-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-krb5-locator-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-krb5-locator-4.0.0-58.el6.rc4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-krb5-locator-4.0.0-58.el6.rc4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
  }
}
