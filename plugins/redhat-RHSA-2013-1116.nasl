#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1116. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78966);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-2219");
  script_osvdb_id(95827);
  script_xref(name:"RHSA", value:"2013:1116");

  script_name(english:"RHEL 5 : redhat-ds-base (RHSA-2013:1116)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated redhat-ds-base packages that fix one security issue and
several bugs are now available for Red Hat Directory Server 8.2.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

It was discovered that Red Hat Directory Server did not honor defined
attribute access controls when evaluating search filter expressions. A
remote attacker (with permission to query the Directory Server) could
use this flaw to determine the values of restricted attributes via a
series of search queries with filter conditions that used restricted
attributes. (CVE-2013-2219)

This issue was discovered by Ludwig Krispenz of Red Hat.

This update also fixes the following bugs :

* Prior to this update, the replication of the schema failed because
of the attribute 'unhashed#user#password,' which had an invalid name.
When this problem happened, the error logs recorded the message
'Schema replication update failed: Invalid syntax.' This update allows
this attribute's name and the replication of the schema. (BZ#970934)

* Prior to this update, under high load of incoming connections and
due to a race condition, a connection which was not yet fully
initialized could start being polled. This would lead to a crash. This
update ensures that the connection is fully initialized before being
in the polling set. (BZ#954051)

* Prior to this update, if some requested attributes were skipped
during a search (for example, because of an ACI), the returned
attribute names and values could be shifted. This update removes
attributes that are not authorized from the requested attributes set,
so that the returned attributes/values are not shifted. (BZ#922773)

* Prior to this update, when an attribute was configured to be
encrypted, online import failed to store it in an encrypted way. This
update allows encryption, on the consumer side, during an online
import. (BZ#893178)

* Prior to this update, updating the redhat-ds-base package resulted
in the '/etc/dirsrv/slapd-[instance]/certmap.conf' file being
overwritten with the default template. With this update, upgrading the
redhat-ds-base package no longer causes
'/etc/dirsrv/slapd-[instance]/certmap.conf' to be overwritten if the
file already exists, preventing users from losing their custom
changes. (BZ#919154)

All users of Red Hat Directory Server 8.2 are advised to upgrade to
these updated packages, which fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2219.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1116.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected redhat-ds-base and / or redhat-ds-base-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:1116";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"redhat-ds-base-8.2.11-13.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"redhat-ds-base-8.2.11-13.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"redhat-ds-base-devel-8.2.11-13.el5dsrv")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"redhat-ds-base-devel-8.2.11-13.el5dsrv")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redhat-ds-base / redhat-ds-base-devel");
  }
}
