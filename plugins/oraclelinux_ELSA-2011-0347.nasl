#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0347 and 
# Oracle Linux Security Advisory ELSA-2011-0347 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68229);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/31 14:53:42 $");

  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
  script_bugtraq_id(46363);
  script_osvdb_id(72528, 72529, 72530);
  script_xref(name:"RHSA", value:"2011:0347");

  script_name(english:"Oracle Linux 6 : openldap (ELSA-2011-0347)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0347 :

Updated openldap packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

A flaw was found in the way OpenLDAP handled authentication failures
being passed from an OpenLDAP slave to the master. If OpenLDAP was
configured with a chain overlay and it forwarded authentication
failures, OpenLDAP would bind to the directory as an anonymous user
and return success, rather than return failure on the authenticated
bind. This could allow a user on a system that uses LDAP for
authentication to log into a directory-based account without knowing
the password. (CVE-2011-1024)

It was found that the OpenLDAP back-ndb back end allowed successful
authentication to the root distinguished name (DN) when any string was
provided as a password. A remote user could use this flaw to access an
OpenLDAP directory if they knew the value of the root DN. Note: This
issue only affected OpenLDAP installations using the NDB back-end,
which is only available for Red Hat Enterprise Linux 6 via third-party
software. (CVE-2011-1025)

A flaw was found in the way OpenLDAP handled modify relative
distinguished name (modrdn) requests. A remote, unauthenticated user
could use this flaw to crash an OpenLDAP server via a modrdn request
containing an empty old RDN value. (CVE-2011-1081)

Users of OpenLDAP should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the OpenLDAP daemons will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-March/001995.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"compat-openldap-2.3.43-2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-clients-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-devel-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-servers-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-servers-sql-2.4.19-15.el6_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
}
