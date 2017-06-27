#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-395.
#

include("compat.inc");

if (description)
{
  script_id(24926);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:54:56 $");

  script_xref(name:"FEDORA", value:"2007-395");

  script_name(english:"Fedora Core 5 : openssh-4.3p2-4.12.fc5 (2007-395)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Mar 30 2007 Miloslav Trmac <mitr at redhat.com> -
    4.3p2-4.12

    - Fix an information leak in Kerberos password
      authentication (CVE-2006-5052) Resolves: #234640

  - Fri Nov 10 2006 Tomas Mraz <tmraz at redhat.com> -
    4.3p2-4.11

    - CVE-2006-5794 - properly detect failed key verify in
      monitor (#214641)

    - kill all ssh sessions when stop is called in halt or
      reboot runlevel (#213008)

    - remove -TERM option from killproc so we don't race on
      sshd restart (#213490)

    - Mon Oct 2 2006 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-4.10

    - improve gssapi-no-spnego patch (#208102)

    - CVE-2006-4924 - prevent DoS on deattack detector
      (#207957)

    - CVE-2006-5051 - don't call cleanups from signal
      handler (#208459)

    - Wed Sep 13 2006 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-4.1

    - sync with FC6 version

    - build for FC5

    - Wed Aug 23 2006 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-9

    - don't report duplicate syslog messages, use correct
      local time (#189158)

    - don't allow spnego as gssapi mechanism (from upstream)

    - fixed memleaks found by Coverity (from upstream)

    - allow ip options except source routing (#202856)
      (patch by HP)

    - Tue Aug 8 2006 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-8

    - drop the pam-session patch from the previous build
      (#201341)

    - don't set IPV6_V6ONLY sock opt when listening on
      wildcard addr (#201594)

    - Thu Jul 20 2006 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-7

    - dropped old ssh obsoletes

    - call the pam_session_open/close from the monitor when
      privsep is enabled so it is always called as root
      (patch by Darren Tucker)

  - Mon Jul 17 2006 Tomas Mraz <tmraz at redhat.com> -
    4.3p2-6

    - improve selinux patch (by Jan Kiszka)

    - upstream patch for buffer append space error (#191940)

    - fixed typo in configure.ac (#198986)

    - added pam_keyinit to pam configuration (#198628)

    - improved error message when askpass dialog cannot grab
      keyboard input (#198332)

  - buildrequires xauth instead of xorg-x11-xauth

    - fixed a few rpmlint warnings

    - Wed Jul 12 2006 Jesse Keating <jkeating at redhat.com>
      - 4.3p2-5.1

    - rebuild

    - Fri Apr 14 2006 Tomas Mraz <tmraz at redhat.com> -
      4.3p2-5

    - don't request pseudoterminal allocation if stdin is
      not tty (#188983)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-April/001635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b32df14"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"openssh-4.3p2-4.12.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"openssh-askpass-4.3p2-4.12.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"openssh-clients-4.3p2-4.12.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"openssh-debuginfo-4.3p2-4.12.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"openssh-server-4.3p2-4.12.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-debuginfo / etc");
}
