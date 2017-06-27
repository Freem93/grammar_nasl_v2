#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-1307.
#

include("compat.inc");

if (description)
{
  script_id(30236);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:13:37 $");

  script_cve_id("CVE-2007-6698");
  script_xref(name:"FEDORA", value:"2008-1307");

  script_name(english:"Fedora 7 : openldap-2.3.34-6.fc7 (2008-1307)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Feb 5 2008 Jan Safranek <jsafranek at redhat.com>
    2.3.34-6

    - fix CVE-2007-6698 (#431409)

    - Mon Jan 14 2008 Jan Safranek <jsafranek at redhat.com>
      2.3.34-5

    - fix default slurpd directory to /var/lib/ldap
      (#424831)

    - Fri Nov 2 2007 Jan Safranek <jsafranek at redhat.com>
      2.3.34-4

    - fix various security flaws (#360081)

    - Fri Jul 13 2007 Jan Safranek <jsafranek at redhat.com>
      2.3.34-3

    - Fix initscript return codes (#242667)

    - Provide overlays including smbk5pwd (as modules;
      #246036, #245896, #220895)

    - Add available modules to config file

    - do not create script in /tmp on startup (bz#188298)

    - add compat-slapcat to openldap-compat (bz#179378)

    - do not import ddp services with migrate_services.pl
      (bz#201183)

  - sort the hosts by address, preventing duplicities in
    migrate*nis*.pl (bz#201540)

  - start slupd for each replicated database (bz#210155)

    - add ldconfig to devel post/postun (bz#240253)

    - include misc.schema in default slapd.conf (bz#147805)

    - Mon Apr 23 2007 Jan Safranek <jsafranek at redhat.com>
      2.3.34-2

    - slapadd during package update is now quiet (bz#224581)

    - use _localstatedir instead of var/ during build
      (bz#220970)

    - bind-libbind-devel removed from BuildRequires
      (bz#216851)

    - slaptest is now quiet during service ldap start, if
      there is no error/warning (bz#143697)

  - libldap_r.so now links with pthread (bz#198226)

    - do not strip binaries to produce correct .debuginfo
      packages (bz#152516)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431203"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007486.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3703ef3b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"openldap-2.3.34-6.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap");
}
