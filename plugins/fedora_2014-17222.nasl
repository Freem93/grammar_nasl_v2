#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-17222.
#

include("compat.inc");

if (description)
{
  script_id(80375);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:23:31 $");

  script_cve_id("CVE-2014-3580", "CVE-2014-8108");
  script_bugtraq_id(71725, 71726);
  script_xref(name:"FEDORA", value:"2014-17222");

  script_name(english:"Fedora 20 : subversion-1.8.11-1.fc20 (2014-17222)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of **Apache
Subversion**, version **1.8.11**. Two security issues in mod_dav_svn
are addressed in this release (CVE-2014-8108, CVE-2014-3580). For more
details, see :

http://subversion.apache.org/security/CVE-2014-8108-advisory.txt
http://subversion.apache.org/security/CVE-2014-3580-advisory.txt

**Client-side bugfixes:**

  - checkout/update: fix file externals failing to follow
    history and subsequently silently failing
    http://subversion.tigris.org/issues/show_bug.cgi?id=4185

    - patch: don't skip targets in valid --git difs

    - diff: make property output in diffs stable

    - diff: fix diff of local copied directory with props

    - diff: fix changelist filter for repos-WC and WC-WC

    - remove broken conflict resolver menu options that
      always error out

    - improve gpg-agent support

    - fix crash in eclipse IDE with GNOME Keyring
      http://subversion.tigris.org/issues/show_bug.cgi?id=34
      98

    - fix externals shadowing a versioned directory
      http://subversion.tigris.org/issues/show_bug.cgi?id=40
      85

    - fix problems working on unix file systems that don't
      support permissions

    - upgrade: keep external registrations
      http://subversion.tigris.org/issues/show_bug.cgi?id=45
      19

    - cleanup: iprove performance of recorded timestamp
      fixups

    - translation updates for German

**Server-side bugfixes:**

  - disable revprop caching feature due to cache
    invalidation problems

    - skip generating uniquifiers if rep-sharing is not
      supported

    - mod_dav_svn: reject requests with missing repository
      paths

    - mod_dav_svn: reject requests with invalid virtual
      transaction names

    - mod_dav_svn: avoid unneeded memory growth in resource
      walking
      http://subversion.tigris.org/issues/show_bug.cgi?id=45
      31

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2014-3580-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2014-8108-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=3498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1174054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1174057"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-January/147506.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13f2a8df"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC20", reference:"subversion-1.8.11-1.fc20")) flag++;


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
