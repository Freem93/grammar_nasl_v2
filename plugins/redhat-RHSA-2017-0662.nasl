#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0662. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97880);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2016-2125", "CVE-2016-2126");
  script_osvdb_id(149001, 149002);
  script_xref(name:"RHSA", value:"2017:0662");

  script_name(english:"RHEL 6 : samba (RHSA-2017:0662)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* It was found that Samba always requested forwardable tickets when
using Kerberos authentication. A service to which Samba authenticated
using Kerberos could subsequently use the ticket to impersonate Samba
to other services or domain users. (CVE-2016-2125)

* A flaw was found in the way Samba handled PAC (Privilege Attribute
Certificate) checksums. A remote, authenticated attacker could use
this flaw to crash the winbindd process. (CVE-2016-2126)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2126.html"
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfcf474c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2126.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0662.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2017:0662";
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
  if (rpm_check(release:"RHEL6", reference:"libsmbclient-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libsmbclient-devel-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-client-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-client-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-common-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-debuginfo-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-doc-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-doc-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-doc-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-domainjoin-gui-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-domainjoin-gui-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-glusterfs-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-swat-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-swat-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-swat-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-winbind-clients-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-winbind-devel-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-krb5-locator-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-krb5-locator-3.6.23-41.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.23-41.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
  }
}
