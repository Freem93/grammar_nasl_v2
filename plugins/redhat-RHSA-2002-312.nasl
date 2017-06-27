#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:312. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12346);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-1378", "CVE-2002-1379", "CVE-2002-1508");
  script_xref(name:"RHSA", value:"2002:312");

  script_name(english:"RHEL 2.1 : openldap (RHSA-2002:312)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenLDAP packages are available which fix a number of local
and remote buffer overflows in libldap as well as the slapd and slurpd
daemons. Additionally, potential issues stemming from using
user-specified LDAP configuration files have been addressed.

[Updated 06 Feb 2003] Added fixed packages for Red Hat Linux Advanced
Workstation 2.1

[Updated 13 Aug 2003] Added openldap12 packages for Red Hat Linux
Advanced Server 2.1 and Advanced Workstation 2.1 that were originally
left out of this errata.

OpenLDAP is a suite of LDAP (Lightweight Directory Access Protocol)
applications and development tools. LDAP is a set of protocols for
accessing directory services. In an audit of OpenLDAP by SuSE, a
number of potential security issues were found.

The following is a list of these issues :

When reading configuration files, libldap reads the current user's
.ldaprc file even in applications being run with elevated privileges.

Slurpd would overflow an internal buffer if the command-line argument
used with the -t or -r flags is too long, or if the name of a file for
which it attempted to create an advisory lock is too long.

When parsing filters, the getfilter family of functions from libldap
can overflow an internal buffer by supplying a carefully crafted
ldapfilter.conf file.

When processing LDAP entry display templates, libldap can overflow an
internal buffer by supplying a carefully crafted ldaptemplates.conf
file.

When parsing an access control list, slapd can overflow an internal
buffer.

When constructing the name of the file used for logging rejected
replication requests, slapd overflows an internal buffer if the size
of the generated name is too large. It can also destroy the contents
of any file owned by the user 'ldap' due to a race condition in the
subsequent creation of the log file.

All of these potential security issues are corrected by the packages
contained within this erratum.

Red Hat Linux Advanced Server users who use LDAP are advised to
install the updated OpenLDAP packages contained within this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1378.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1379.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-312.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:312";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-2.0.27-2.7.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-clients-2.0.27-2.7.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-devel-2.0.27-2.7.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap-servers-2.0.27-2.7.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"openldap12-1.2.13-8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-devel / openldap-servers / etc");
  }
}
