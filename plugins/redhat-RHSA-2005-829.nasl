#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:829. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20146);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 18:06:54 $");

  script_cve_id("CVE-2004-0079");
  script_osvdb_id(4317);
  script_xref(name:"RHSA", value:"2005:829");

  script_name(english:"RHEL 2.1 : openssl (RHSA-2005:829)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that fix a remote denial of service
vulnerability are now available for Red Hat Enterprise Linux 2.1

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The OpenSSL toolkit implements Secure Sockets Layer (SSL v2/v3),
Transport Layer Security (TLS v1) protocols, and serves as a
full-strength general purpose cryptography library.

Testing performed by the OpenSSL group using the Codenomicon TLS Test
Tool uncovered a NULL pointer assignment in the
do_change_cipher_spec() function. A remote attacker could perform a
carefully crafted SSL/TLS handshake against a server that uses the
OpenSSL library in such a way as to cause OpenSSL to crash. Depending
on the server this could lead to a denial of service. (CVE-2004-0079)

This issue was reported as not affecting OpenSSL versions prior to
0.9.6c, and testing with the Codenomicon Test Tool showed that OpenSSL
0.9.6b as shipped in Red Hat Enterprise Linux 2.1 did not crash.
However, an alternative reproducer has been written which shows that
this issue does affect versions of OpenSSL prior to 0.9.6c.

Users of OpenSSL are advised to upgrade to these updated packages,
which contain a patch provided by the OpenSSL group that protects
against this issue.

NOTE: Because server applications are affected by this issue, users
are advised to either restart all services that use OpenSSL
functionality or restart their systems after installing these updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-829.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl095a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl096");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:829";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-0.9.6b-42")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"openssl-0.9.6b-42")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-devel-0.9.6b-42")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl-perl-0.9.6b-42")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl095a-0.9.5a-28")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openssl096-0.9.6-28")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl095a / openssl096");
  }
}
