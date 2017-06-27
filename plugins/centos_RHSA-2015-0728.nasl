#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0728 and 
# CentOS Errata and Security Advisory 2015:0728 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82475);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2015-0283", "CVE-2015-1827");
  script_bugtraq_id(73376, 73377);
  script_xref(name:"RHSA", value:"2015:0728");

  script_name(english:"CentOS 7 : ipa / slapi-nis (CESA-2015:0728)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipa and slapi-nis packages that fix two security issues and
several bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Identity Management is a centralized authentication, identity
management, and authorization solution for both traditional and
cloud-based enterprise environments. It integrates components of the
Red Hat Directory Server, MIT Kerberos, Red Hat Certificate System,
NTP, and DNS. It provides web browser and command-line interfaces. Its
administration tools allow an administrator to quickly install, set
up, and administer a group of domain controllers to meet the
authentication and identity management requirements of large-scale
Linux and UNIX deployments.

The ipa component provides centrally managed Identity, Policy, and
Audit. The slapi-nis component provides NIS Server and Schema
Compatibility plug-ins for Directory Server.

It was discovered that the IPA extdom Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for a list of groups for a user that belongs to
a large number of groups would cause a Directory Server to crash.
(CVE-2015-1827)

It was discovered that the slapi-nis Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for information about a group with many
members, or a request for a user that belongs to a large number of
groups, would cause a Directory Server to enter an infinite loop and
consume an excessive amount of CPU time. (CVE-2015-0283)

These issues were discovered by Sumit Bose of Red Hat.

This update fixes the following bugs :

* Previously, users of IdM were not properly granted the default
permission to read the 'facsimiletelephonenumber' user attribute. This
update adds 'facsimiletelephonenumber' to the Access Control
Instruction (ACI) for user data, which makes the attribute readable to
authenticated users as expected. (BZ#1198430)

* Prior to this update, when a DNS zone was saved in an LDAP database
without a dot character (.) at the end, internal DNS commands and
operations, such as dnsrecord-* or dnszone-*, failed. With this
update, DNS commands always supply the DNS zone with a dot character
at the end, which prevents the described problem. (BZ#1198431)

* After a full-server IdM restore operation, the restored server in
some cases contained invalid data. In addition, if the restored server
was used to reinitialize a replica, the replica then contained invalid
data as well. To fix this problem, the IdM API is now created
correctly during the restore operation, and *.ldif files are not
skipped during the removal of RUV data. As a result, the restored
server and its replica no longer contain invalid data. (BZ#1199060)

* Previously, a deadlock in some cases occurred during an IdM upgrade,
which could cause the IdM server to become unresponsive. With this
update, the Schema Compatibility plug-in has been adjusted not to
parse the subtree that contains the configuration of the DNA plug-in,
which prevents this deadlock from triggering. (BZ#1199128)

* When using the extdom plug-in of IdM to handle large groups, user
lookups and group lookups previously failed due to insufficient buffer
size. With this update, the getgrgid_r() call gradually increases the
buffer length if needed, and the described failure of extdom thus no
longer occurs. (BZ#1203204)

Users of ipa and slapi-nis are advised to upgrade to these updated
packages, which correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?518313cc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?437eab25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ipa and / or slapi-nis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-admintools-4.1.0-18.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-client-4.1.0-18.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-python-4.1.0-18.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-4.1.0-18.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.1.0-18.el7.centos.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"slapi-nis-0.54-3.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
