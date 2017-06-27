#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-13623.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56515);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:56:28 $");

  script_cve_id("CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871");
  script_xref(name:"FEDORA", value:"2011-13623");

  script_name(english:"Fedora 16 : puppet-2.6.6-3.fc16 (2011-13623)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following vulnerabilities have been discovered and fixed :

  - CVE-2011-3870, a symlink attack via a user's SSH
    authorized_keys file

    - CVE-2011-3869, a symlink attack via a user's .k5login
      file

    - CVE-2011-3871, a privilege escalation attack via the
      temp file used by the puppet resource application

    - A low-risk file indirector injection attack

Further details can be found in the upstream announcement :

http://groups.google.com/group/puppet-announce/browse_thread/thread/91
e3b46d2328a1cb A vulnerability was discovered in puppet that would
allow an attacker to install a valid X509 Certificate Signing Request
at any location on disk, with the privileges of the Puppet Master
application. For Fedora and EPEL, this is the puppet user.

Further details can be found in the upstream announcement :

http://groups.google.com/group/puppet-users/browse_thread/thread/e57ce
2740feb9406

Unless you enable puppet's listen mode on clients, only the puppet
master is vulnerable to this issue. A vulnerability was discovered in
puppet that would allow an attacker to install a valid X509
Certificate Signing Request at any location on disk, with the
privileges of the Puppet Master application. For Fedora and EPEL, this
is the puppet user.

Further details can be found in the upstream announcement :

http://groups.google.com/group/puppet-users/browse_thread/thread/e57ce
2740feb9406

Unless you enable puppet's listen mode on clients, only the puppet
master is vulnerable to this issue. A vulnerability was discovered in
puppet that would allow an attacker to install a valid X509
Certificate Signing Request at any location on disk, with the
privileges of the Puppet Master application. For Fedora and EPEL, this
is the puppet user.

Further details can be found in the upstream announcement :

http://groups.google.com/group/puppet-users/browse_thread/thread/e57ce
2740feb9406

Unless you enable puppet's listen mode on clients, only the puppet
master is vulnerable to this issue. A vulnerability was discovered in
puppet that would allow an attacker to install a valid X509
Certificate Signing Request at any location on disk, with the
privileges of the Puppet Master application. For Fedora and EPEL, this
is the puppet user.

Further details can be found in the upstream announcement :

http://groups.google.com/group/puppet-users/browse_thread/thread/e57ce
2740feb9406

Unless you enable puppet's listen mode on clients, only the puppet
master is vulnerable to this issue. A vulnerability was discovered in
puppet that would allow an attacker to install a valid X509
Certificate Signing Request at any location on disk, with the
privileges of the Puppet Master application. For Fedora and EPEL, this
is the puppet user.

Further details can be found in the upstream announcement :

http://groups.google.com/group/puppet-users/browse_thread/thread/e57ce
2740feb9406

Unless you enable puppet's listen mode on clients, only the puppet
master is vulnerable to this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://groups.google.com/group/puppet-announce/browse_thread/thread/91e3b46d2328a1cb
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56b35af7"
  );
  # http://groups.google.com/group/puppet-users/browse_thread/thread/e57ce2740feb9406
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b2f8e47"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/068093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75c1bcfb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected puppet package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"puppet-2.6.6-3.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet");
}
