#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-12421.
#

include("compat.inc");

if (description)
{
  script_id(68887);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 21:02:57 $");

  script_cve_id("CVE-2013-2099");
  script_xref(name:"FEDORA", value:"2013-12421");

  script_name(english:"Fedora 17 : zeroinstall-injector-2.3-1.fc17 (2013-12421)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Enhancements :

  - upstream now ships an experimental OCaml front-end, this
    is not yet enabled

    - Add fish-shell command completion

    - Allow relative files in <archive> and <file> for local
      feeds. This makes it easy to test feeds before passing
      them to 0repo.

Bug fixes :

  - Better handling of default=' in <environment> bindings.
    This now specifies that the default should be ',
    overriding any system default.

    - Fixed --refresh with 'download' and 'run' for apps.

    - Updated ssl_match_hostname based on latest bug-fixes.
      This fix is intended to fix a denial-of-service
      attack, which doesn't really matter to 0install, but
      we might as well have the latest version.
      CVE-2013-2099

    - Better error when the <rename> source does not exist.

    - Allow selecting local archives even in offline mode.

    - Support the use of the system store with recipes. This
      is especially important now that we treat all
      downloads as recipes!

    - Removed old zeroinstall-add.desktop file.

Changes for APIs we depend on

  - Cope with more PyGObject API changes. Based on patch in
    http://twistedmatrix.com/trac/ticket/6369

  - Keep gobject and glib separate. Sometimes we need GLib,
    sometimes we need GObject.

    - Updates to avoid PyGIDeprecationWarning.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://twistedmatrix.com/trac/ticket/6369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=958834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=966273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=966274"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/111600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af358f7b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zeroinstall-injector package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:zeroinstall-injector");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"zeroinstall-injector-2.3-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zeroinstall-injector");
}
