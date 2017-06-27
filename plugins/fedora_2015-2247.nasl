#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-2247.
#

include("compat.inc");

if (description)
{
  script_id(81458);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/08 13:38:43 $");

  script_cve_id("CVE-2014-9680");
  script_xref(name:"FEDORA", value:"2015-2247");

  script_name(english:"Fedora 20 : sudo-1.8.12-1.fc20 (2015-2247)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 1.8.12

    - fixes CVE-2014-9680

Update to 1.8.11p2

Major upstream changes & fixes :

  - when running a command in the background, sudo will now
    forward SIGINFO to the command

    - the passwords in ldap.conf and ldap.secret may now be
      encoded in base64.

    - SELinux role changes are now audited. For sudoedit, we
      now audit the actual editor being run, instead of just
      the sudoedit command.

    - it is now possible to match an environment variable's
      value as well as its name using env_keep and env_check

    - new files created via sudoedit as a non-root user now
      have the proper group id

    - sudoedit now works correctly in conjunction with
      sudo's SELinux RBAC support

    - it is now possible to disable network interface
      probing in sudo.conf by changing the value of the
      probe_interfaces setting

    - when listing a user's privileges (sudo -l), the
      sudoers plugin will now prompt for the user's password
      even if the targetpw, rootpw or runaspw options are
      set.

    - the new use_netgroups sudoers option can be used to
      explicitly enable or disable netgroups support

    - visudo can now export a sudoers file in JSON format
      using the new -x flag

Distribution specific changes :

  - added patch to read ldap.conf more closely to nss_ldap

    - require /usr/bin/vi instead of vim-minimal

    - include pam.d/system-auth in PAM session phase from
      pam.d/sudo

    - include pam.d/sudo in PAM session phase from
      pam.d/sudo-i

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191144"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150327.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1b1eb6e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"sudo-1.8.12-1.fc20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
