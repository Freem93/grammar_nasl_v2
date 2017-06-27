#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1504.
#

include("compat.inc");

if (description)
{
  script_id(24082);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-1504");

  script_name(english:"Fedora Core 5 : dovecot-1.0-0.beta8.3.fc5 (2006-1504)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Dec 21 2006 Tomas Janousek <tjanouse at redhat.com>
    - 1.0-0.beta8.3.fc5

    - fixed default paths in the example mkcert.sh to match
      configuration defaults (fixes #183151)

  - fixed off by one (#216508, CVE-2006-5973)

    - Thu Jun 8 2006 Petr Rockai <prockai at redhat.com> -
      1.0-0.beta8.2.fc5

    - bring FC-5 branch up to date with the rawhide one
      (bugfixes only)

    - should fix non-working pop3 in default installation

    - Thu Jun 8 2006 Petr Rockai <prockai at redhat.com> -
      1.0-0.beta8.2

    - put back pop3_uidl_format default that got lost in the
      beta2->beta7 upgrade (would cause pop3 to not work at
      all in many situations)

  - Thu May 4 2006 Petr Rockai <prockai at redhat.com> -
    1.0-0.beta8.1

    - upgrade to latest upstream beta release (beta8)

    - contains a security fix in mbox handling

    - Thu May 4 2006 Petr Rockai <prockai at redhat.com> -
      1.0-0.beta7.1

    - upgrade to latest upstream beta release

    - fixed BR 173048

    - Fri Mar 17 2006 Petr Rockai <prockai at redhat.com> -
      1.0-0.beta2.8

    - fix sqlite detection in upstream configure checks,
      second part of #182240

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-December/001172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ecd3071"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot and / or dovecot-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dovecot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
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
if (rpm_check(release:"FC5", reference:"dovecot-1.0-0.beta8.3.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"dovecot-debuginfo-1.0-0.beta8.3.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-debuginfo");
}
