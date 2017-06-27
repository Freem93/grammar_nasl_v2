#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-5815.
#

include("compat.inc");

if (description)
{
  script_id(53816);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 22:05:54 $");

  script_cve_id("CVE-2011-1758");
  script_bugtraq_id(47658);
  script_osvdb_id(72113);
  script_xref(name:"FEDORA", value:"2011-5815");

  script_name(english:"Fedora 14 : sssd-1.5.7-1.fc14 (2011-5815)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Apr 29 2011 Stephen Gallagher <sgallagh at
    redhat.com> - 1.5.7-1

    - Resolves: rhbz#700891 - CVE-2011-1758 sssd: automatic
      TGT renewal overwrites

    - cached password with predicatable filename

  - Wed Apr 20 2011 Stephen Gallagher <sgallagh at
    redhat.com> - 1.5.6.1-1

    - Re-add manpage translations

  - Wed Apr 20 2011 Stephen Gallagher <sgallagh at
    redhat.com> - 1.5.6-1

    - New upstream release 1.5.6

    -
      https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.
      6

    - Fixed a serious memory leak in the memberOf plugin

    - Fixed a regression with the negative cache that caused
      it to be essentially

    - nonfunctional

    - Fixed an issue where the user's full name would
      sometimes be removed from

    - the cache

    - Fixed an issue with password changes in the kerberos
      provider not working

    - with kpasswd

    - Resolves: rhbz#697057 - kpasswd fails when using sssd
      and

    - kadmin server != kdc server

    - Fix a serious memory leak in the memberOf plugin

    - Fix an issue where the user's full name would
      sometimes be removed

    - from the cache

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=697057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=700891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-May/059619.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca3f0322"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sssd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/06");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"sssd-1.5.7-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
