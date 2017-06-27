#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0442 and 
# Oracle Linux Security Advisory ELSA-2015-0442 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81806);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_bugtraq_id(70932, 71305);
  script_osvdb_id(112034, 112155);
  script_xref(name:"RHSA", value:"2015:0442");

  script_name(english:"Oracle Linux 7 : ipa (ELSA-2015-0442)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0442 :

Updated ipa packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Two cross-site scripting (XSS) flaws were found in jQuery, which
impacted the Identity Management web administrative interface, and
could allow an authenticated user to inject arbitrary HTML or web
script into the interface. (CVE-2010-5312, CVE-2012-6662)

Note: The IdM version provided by this update no longer uses jQuery.

This update adds several enhancements that are described in more
detail in the Red Hat Enterprise Linux 7.1 Release Notes, linked to in
the References section, including :

* Added the 'ipa-cacert-manage' command, which renews the
Certification Authority (CA) file. (BZ#886645)

* Added the ID Views feature. (BZ#891984)

* IdM now supports using one-time password (OTP) authentication and
allows gradual migration from proprietary OTP solutions to the IdM OTP
solution. (BZ#919228)

* Added the 'ipa-backup' and 'ipa-restore' commands to allow manual
backups. (BZ#951581)

* Added a solution for regulating access permissions to specific
sections of the IdM server. (BZ#976382)

This update also fixes several bugs, including :

* Previously, when IdM servers were configured to require the
Transport Layer Security protocol version 1.1 (TLSv1.1) or later in
the httpd server, the 'ipa' command-line utility failed. With this
update, running 'ipa' works as expected with TLSv1.1 or later.
(BZ#1156466)

In addition, this update adds multiple enhancements, including :

* The 'ipa-getkeytab' utility can now optionally fetch existing
keytabs from the KDC. Previously, retrieving an existing keytab was
not supported, as the only option was to generate a new key.
(BZ#1007367)

* You can now create and manage a '.' root zone on IdM servers. DNS
queries sent to the IdM DNS server use this configured zone instead of
the public zone. (BZ#1056202)

* The IdM server web UI has been updated and is now based on the
Patternfly framework, offering better responsiveness. (BZ#1108212)

* A new user attribute now enables provisioning systems to add custom
tags for user objects. The tags can be used for automember rules or
for additional local interpretation. (BZ#1108229)

* This update adds a new DNS zone type to ensure that forward and
master zones are better separated. As a result, the IdM DNS interface
complies with the forward zone semantics in BIND. (BZ#1114013)

* This update adds a set of Apache modules that external applications
can use to achieve tighter interaction with IdM beyond simple
authentication. (BZ#1107555)

* IdM supports configuring automember rules for automated assignment
of users or hosts in respective groups according to their
characteristics, such as the 'userClass' or 'departmentNumber'
attributes. Previously, the rules could be applied only to new
entries. This update allows applying the rules also to existing users
or hosts. (BZ#1108226)

* The extdom plug-in translates Security Identifiers (SIDs) of Active
Directory (AD) users and groups to names and POSIX IDs. With this
update, extdom returns the full member list for groups and the full
list of group memberships for a user, the GECOS field, the home
directory, as well as the login shell of a user. Also, an optional
list of key-value pairs contains the SID of the requested object if
the SID is available. (BZ#1030699)

All ipa users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004885.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-admintools-4.1.0-18.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-client-4.1.0-18.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-python-4.1.0-18.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-4.1.0-18.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.1.0-18.0.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-python / ipa-server / etc");
}
