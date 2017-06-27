#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1542. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71002);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-0213", "CVE-2013-0214", "CVE-2013-4124");
  script_bugtraq_id(57631, 61597);
  script_osvdb_id(89626, 89627, 95969);
  script_xref(name:"RHSA", value:"2013:1542");

  script_name(english:"RHEL 6 : samba (RHSA-2013:1542)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix three security issues, several bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

It was discovered that the Samba Web Administration Tool (SWAT) did
not protect against being opened in a web page frame. A remote
attacker could possibly use this flaw to conduct a clickjacking attack
against SWAT users or users with an active SWAT session.
(CVE-2013-0213)

A flaw was found in the Cross-Site Request Forgery (CSRF) protection
mechanism implemented in SWAT. An attacker with the knowledge of a
victim's password could use this flaw to bypass CSRF protections and
conduct a CSRF attack against the victim SWAT user. (CVE-2013-0214)

An integer overflow flaw was found in the way Samba handled an
Extended Attribute (EA) list provided by a client. A malicious client
could send a specially crafted EA list that triggered an overflow,
causing the server to loop and reprocess the list using an excessive
amount of memory. (CVE-2013-4124)

Note: This issue did not affect the default configuration of the Samba
server.

Red Hat would like to thank the Samba project for reporting
CVE-2013-0213 and CVE-2013-0214. Upstream acknowledges Jann Horn as
the original reporter of CVE-2013-0213 and CVE-2013-0214.

These updated samba packages include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All samba users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement. After installing this update, the smb service will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4124.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1542.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
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
  rhsa = "RHSA-2013:1542";
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
  if (rpm_check(release:"RHEL6", reference:"libsmbclient-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libsmbclient-devel-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-client-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-client-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-client-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-common-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-debuginfo-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-doc-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-doc-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-doc-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-domainjoin-gui-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-domainjoin-gui-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-domainjoin-gui-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-swat-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-swat-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-swat-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-winbind-clients-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"samba-winbind-devel-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba-winbind-krb5-locator-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba-winbind-krb5-locator-3.6.9-164.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba-winbind-krb5-locator-3.6.9-164.el6")) flag++;

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
