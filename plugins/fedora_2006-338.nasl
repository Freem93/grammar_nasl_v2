#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-338.
#

include("compat.inc");

if (description)
{
  script_id(21249);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_cve_id("CVE-2006-1057");
  script_xref(name:"FEDORA", value:"2006-338");

  script_name(english:"Fedora Core 5 : gdm-2.14.1-1.fc5.2 (2006-338)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"(Notes taken from upstream release mail)

  - The sockets connection between the slaves and the GDM
    daemon is now better managed to better ensure that
    sockets are never left open. (Brian Cameron)

  - Corrected bug that causes a core dump when you click on
    gdmgreeter fields that have an id. (Brian Cameron)

  - Add new GdmXserverTimeout configuration setting so that
    the length of time GDM waits for the Xserver to start
    can be tuned, so GDM better works with Xservers that
    require more than 10 seconds to start. (Emilie)

  - The happygnome and happygnome-list gdmgreeter themes now
    use the official logo. (Brian Cameron)

  - Now GDM configure supports --with-sysconfsubdir so that
    GDM's configuration directory can be configured to not
    have '/gdm' appended to the end.

  - Fix for ensuring .ICEauthority file has proper
    ownership/permissions. Addresses CVE-2006-1057. (Hans
    Petter Jansson)

  - Fix 'Show Actions Menu' section in gdmsetup so it
    appears when both 'Plain' and 'Themed' style is chosen.
    (Brian Cameron, Dennis Cranston)

  - Now use LINGUAS procedure for defining languages.
    (Michiel Sikkes)

  - Now Xsession script uses '$@' instead of '$1' so it is
    possible to pass arguments with the command to run.
    (Brian Cameron)

  - Add Trusted Solraris support. (Niall Power)

  - One line fix to Solaris auditing logic that fixes a bug
    causing authentication to fail when auditing is turned
    on. (Brian Cameron)

  - Fixes to compile with C99 and fixes to compile under
    NetBSD. Remove EXPANDED_* variables from the configure.
    (Julio M. Merino Vidal)

  - Translation updates (Aygimantas Beruaka, Benoat Dejean,
    Laurent Dhima, Maxim Dziumanenko, Alessio Frusciante,
    Rhys Jones, Raphael Higino, Theppitak Karoonboonyanan,
    Gabor Kelmen, Priit Laes, Jordi Mallach, Kjartan Maraas,
    Daniel Nylander, Kostas Papdimas, Guilherme de S.
    Pastore, Ankit Patel, Ignacio Casal Quinteiro, Hendrik
    Richter, Jens Seidel, Francisco Javier F. Serrador,
    Alexander Shopov, Clytie Siddall, Ilkka Tuohela, Vincent
    van Adrighem, Tommi Vainikaninen)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-April/002123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?538a4792"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdm and / or gdm-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC5", reference:"gdm-2.14.1-1.fc5.2")) flag++;
if (rpm_check(release:"FC5", reference:"gdm-debuginfo-2.14.1-1.fc5.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-debuginfo");
}
