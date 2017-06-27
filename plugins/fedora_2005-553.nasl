#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-553.
#

include("compat.inc");

if (description)
{
  script_id(18685);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 21:38:05 $");

  script_cve_id("CVE-2005-1689");
  script_xref(name:"FEDORA", value:"2005-553");

  script_name(english:"Fedora Core 4 : krb5-1.4.1-5 (2005-553)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A double-free flaw was found in the krb5_recvauth() routine which may
be triggered by a remote unauthenticated attacker. Fedora Core 4
contains checks within glibc that detect double-free flaws. Therefore,
on Fedora Core 4, successful exploitation of this issue can only lead
to a denial of service (KDC crash). The Common Vulnerabilities and
Exposures project assigned the name CVE-2005-1689 to this issue.

Daniel Wachdorf discovered a single byte heap overflow in the
krb5_unparse_name() function, part of krb5-libs. Successful
exploitation of this flaw would lead to a denial of service (crash).
To trigger this flaw remotely, an attacker would need to have control
of a kerberos realm that shares a cross-realm key with the target,
making exploitation of this flaw unlikely. (CVE-2005-1175).

Daniel Wachdorf also discovered that in error conditions that may
occur in response to correctly-formatted client requests, the Kerberos
5 KDC may attempt to free uninitialized memory. This could allow a
remote attacker to cause a denial of service (KDC crash)
(CVE-2005-1174).

Gaael Delalleau discovered an information disclosure issue in the way
some telnet clients handle messages from a server. An attacker could
construct a malicious telnet server that collects information from the
environment of any victim who connects to it using the Kerberos-aware
telnet client (CVE-2005-0488).

The rcp protocol allows a server to instruct a client to write to
arbitrary files outside of the current directory. This could
potentially cause a security issue if a user uses the Kerberos-aware
rcp to copy files from a malicious server (CVE-2004-0175).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-July/001064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04b2cbe5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"krb5-debuginfo-1.4.1-5")) flag++;
if (rpm_check(release:"FC4", reference:"krb5-devel-1.4.1-5")) flag++;
if (rpm_check(release:"FC4", reference:"krb5-libs-1.4.1-5")) flag++;
if (rpm_check(release:"FC4", reference:"krb5-server-1.4.1-5")) flag++;
if (rpm_check(release:"FC4", reference:"krb5-workstation-1.4.1-5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-server / etc");
}
