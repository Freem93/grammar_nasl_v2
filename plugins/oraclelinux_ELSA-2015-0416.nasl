#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0416 and 
# Oracle Linux Security Advisory ELSA-2015-0416 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81724);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 16:04:32 $");

  script_cve_id("CVE-2014-8105", "CVE-2014-8112");
  script_bugtraq_id(69149, 72985, 73033);
  script_xref(name:"RHSA", value:"2015:0416");

  script_name(english:"Oracle Linux 7 : 389-ds-base (ELSA-2015-0416)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0416 :

Updated 389-ds-base packages that fix two security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

An information disclosure flaw was found in the way the 389 Directory
Server stored information in the Changelog that is exposed via the
'cn=changelog' LDAP sub-tree. An unauthenticated user could in certain
cases use this flaw to read data from the Changelog, which could
include sensitive information such as plain-text passwords.
(CVE-2014-8105)

It was found that when the nsslapd-unhashed-pw-switch 389 Directory
Server configuration option was set to 'off', it did not prevent the
writing of unhashed passwords into the Changelog. This could
potentially allow an authenticated user able to access the Changelog
to read sensitive information. (CVE-2014-8112)

The CVE-2014-8105 issue was discovered by Petr Spacek of the Red Hat
Identity Management Engineering Team, and the CVE-2014-8112 issue was
discovered by Ludwig Krispenz of the Red Hat Identity Management
Engineering Team.

Enhancements :

* Added new WinSync configuration parameters: winSyncSubtreePair for
synchronizing multiple subtrees, as well as winSyncWindowsFilter and
winSyncDirectoryFilter for synchronizing restricted sets by filters.
(BZ# 746646)

* It is now possible to stop, start, or configure plug-ins without the
need to restart the server for the change to take effect. (BZ#994690)

* Access control related to the MODDN and MODRDN operations has been
updated: the source and destination targets can be specified in the
same access control instruction. (BZ#1118014)

* The nsDS5ReplicaBindDNGroup attribute for using a group
distinguished name in binding to replicas has been added. (BZ#1052754)

* WinSync now supports range retrieval. If more than the MaxValRange
number of attribute values exist per attribute, WinSync synchronizes
all the attributes to the directory server using the range retrieval.
(BZ#1044149)

* Support for the RFC 4527 Read Entry Controls and RFC 4533 Content
Synchronization Operation LDAP standards has been added. (BZ#1044139,
BZ#1044159)

* The Referential Integrity (referint) plug-in can now use an
alternate configuration area. The PlugInArg plug-in configuration now
uses unique configuration attributes. Configuration changes no longer
require a server restart. (BZ#1044203)

* The logconv.pl log analysis tool now supports gzip, bzip2, and xz
compressed files and also TAR archives and compressed TAR archives of
these files. (BZ#1044188)

* Only the Directory Manager could add encoded passwords or force
users to change their password after a reset. Users defined in the
passwordAdminDN attribute can now also do this. (BZ#1118007)

* The 'nsslapd-memberofScope' configuration parameter has been added
to the MemberOf plug-in. With MemberOf enabled and a scope defined,
moving a group out of scope with a MODRDN operation failed. Moving a
member entry out of scope now correctly removes the memberof value.
(BZ#1044170)

* The alwaysRecordLoginAttr attribute has been addded to the Account
Policy plug-in configuration entry, which allows to distinguish
between an attribute for checking the activity of an account and an
attribute to be updated at successful login. (BZ#1060032)

* A root DSE search, using the ldapsearch command with the '-s base -b
''' options, returns only the user attributes instead of the
operational attributes. The 'nsslapd-return-default' option has been
added for backward compatibility. (BZ#1118021)

* The configuration of the MemberOf plug-in can be stored in a suffix
mapped to a back-end database, which allows MemberOf configuration to
be replicated. (BZ#1044205)

* Added support for the SSL versions from the range supported by the
NSS library available on the system. Due to the POODLE vulnerability,
SSLv3 is disabled by default even if NSS supports it. (BZ#1044191)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004876.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-1.3.3.1-13.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.3.1-13.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.3.1-13.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
