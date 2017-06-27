#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-16148.
#

include("compat.inc");

if (description)
{
  script_id(50396);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:13:52 $");

  script_cve_id("CVE-2010-3315");
  script_bugtraq_id(43678);
  script_xref(name:"FEDORA", value:"2010-16148");

  script_name(english:"Fedora 14 : subversion-1.6.13-1.fc14 (2010-16148)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of Subversion, version
1.6.13.

Subversion servers up to 1.6.12 (inclusive) making use of the
'SVNPathAuthz short_circuit' mod_dav_svn configuration setting have a
bug which may allow users to write and/or read portions of the
repository to which they are not intended to have access. This issue
is fixed in this update.

See http://subversion.apache.org/security/CVE-2010-3315-advisory.txt
for further details

A number of bug fixes are also included :

  - don't drop properties during foreign-repo merges

    - improve auto-props failure error message

    - improve error message for 403 status with ra_neon

    - don't allow 'merge --reintegrate' for 2-url merges

    - improve handling of missing fsfs.conf during hotcopy

    - escape unsafe characters in a URL during export

    - don't leak stale locks in FSFS

    - better detect broken working copies during update over
      ra_neon

    - fsfs: make rev files read-only

    - properly canonicalize a URL

    - fix wc corruption with 'commit --depth=empty'

    - permissions fixes when doing reintegrate merges

    - fix mergeinfo miscalculation during 2-url merges

    - fix error transmission problems in svnserve

    - fixed: record-only merges create self-referential
      mergeinfo

    - make 'svnmucc propset' handle existing and
      non-existing URLs

    - add new 'propsetf' subcommand to svnmucc

    - emit a warning about copied dirs during ci with
      limited depth

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2010-3315-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=640317"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/050025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01c331e0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC14", reference:"subversion-1.6.13-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
