#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14466);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_xref(name:"GLSA", value:"200404-01");

  script_name(english:"GLSA-200404-01 : Insecure sandbox temporary lockfile vulnerabilities in Portage");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200404-01
(Insecure sandbox temporary lockfile vulnerabilities in Portage)

    A flaw in Portage's sandbox wrapper has been found where the temporary
    lockfiles are subject to a hard-link attack which allows linkable files to
    be overwritten to an empty file. This can be used to damage critical files
    on a system causing a Denial of Service, or alternatively this attack may
    be used to cause other security risks; for example firewall configuration
    data could be overwritten without notice.
    The vulnerable sandbox functions have been patched to test for these new
    conditions: namely; for the existence of a hard-link which would be removed
    before the sandbox process would continue, for the existence of a
    world-writable lockfile in which case the sandbox would also remove it, and
    also for any mismatches in the UID ( anything but root ) and the GID (
    anything but the group of the sandbox process ).
    If the vulnerable files cannot be removed by the sandbox, then the sandbox
    would exit with a fatal error warning the administrator of the issue. The
    patched functions also fix any other sandbox I/O operations which do not
    explicitly include the mentioned lockfile.
  
Impact :

    Any user with write access to the /tmp directory can hard-link a file to
    /tmp/sandboxpids.tmp - this file would eventually be replaced with an empty
    one; effectively wiping out the file it was linked to as well with no prior
    warning. This could be used to potentially disable a vital component of the
    system and cause a path for other possible exploits.
    This vulnerability only affects systems that have /tmp on the root
    partition: since symbolic link attacks are filtered, /tmp has to be on the
    same partition for an attack to take place.
  
Workaround :

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users should upgrade to Portage 2.0.50-r3 or later:
    # emerge sync
    # emerge -pv '>=sys-apps/portage-2.0.50-r3'
    # emerge '>=sys-apps/portage-2.0.50-r3'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:portage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"sys-apps/portage", unaffected:make_list("ge 2.0.50-r3"), vulnerable:make_list("lt 2.0.50-r3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sys-apps/portage");
}
