#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-837.
#

include("compat.inc");

if (description)
{
  script_id(24154);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:27 $");

  script_xref(name:"FEDORA", value:"2006-837");

  script_name(english:"Fedora Core 5 : sendmail-8.13.7-2.fc5.1 (2006-837)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Jul 18 2006 Thomas Woerner <twoerner at redhat.com>
    8.13.7-2.fc5.1

    - using new syntax for access database (#177566)

    - fixed failure message while shutting down sm-client
      (#119429) resolution: stop sm-client before sendmail

  - fixed method to specify persistent queue runners
    (#126760)

    - removed patch backup files from sendmail-cf tree
      (#152955)

    - fixed missing dnl on SMART_HOST define (#166680)

    - fixed wrong location of aliases and aliases.db file in
      aliases man page (#166744)

  - enabled CipherList config option for sendmail (#172352)

    - added user chowns for /etc/mail/authinfo.db and move
      check for cf files (#184341)

  - fixed Makefile of vacation (#191396) vacation is not
    included in this sendmail package

  - /var/log/mail now belongs to sendmail (#192850)

    - Wed Jul 12 2006 Jesse Keating <jkeating at redhat.com>
      - 8.13.7-2.1

    - rebuild

    - Mon Jun 19 2006 Thomas Woerner <twoerner at
      redhat.com> 8.13.7-2

    - dropped reference to Red Hat Linux in
      sendmail-redhat.mc (#176679)

    - Mon Jun 19 2006 Thomas Woerner <twoerner at
      redhat.com> 8.13.7-1

    - new version 8.13.7 (#195282)

    - fixes CVE-2006-1173 (VU#146718): possible denial of
      service issue caused by malformed multipart messages
      (#195776)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-July/000439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1492cf11"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/18");
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
if (rpm_check(release:"FC5", reference:"sendmail-8.13.7-2.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-cf-8.13.7-2.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-debuginfo-8.13.7-2.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-devel-8.13.7-2.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-doc-8.13.7-2.fc5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sendmail / sendmail-cf / sendmail-debuginfo / sendmail-devel / etc");
}
