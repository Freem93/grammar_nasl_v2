#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-6efa349a85.
#

include("compat.inc");

if (description)
{
  script_id(89276);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 16:42:53 $");

  script_cve_id("CVE-2015-3184", "CVE-2015-5259", "CVE-2015-5343");
  script_xref(name:"FEDORA", value:"2015-6efa349a85");

  script_name(english:"Fedora 22 : subversion-1.8.15-1.fc22 (2015-6efa349a85)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of _Apache Subversion
1.8_, version **1.8.15**. This update fixes two security issues: *
**CVE-2015-3184**: Subversion's mod_authz_svn does not properly
restrict anonymous access in some mixed anonymous/authenticated
environments when using Apache httpd 2.4.
http://subversion.apache.org/security/CVE-2015-3184-advisory.txt *
**CVE-2015-3187**: Subversion servers, both httpd and svnserve, will
reveal some paths that should be hidden by path-based authz.
http://subversion.apache.org/security/CVE-2015-3187-advisory.txt ###
User- visible changes: #### Client-side bugfixes: * gpg-agent: fix
crash with non- canonical $HOME * document svn:autoprops * cp: fix
'svn cp ^/A/D/H at 1 ^/A' to properly create A * resolve: improve
conflict prompts for binary files * ls: improve performance of '-v' on
tag directories * improved Sqlite 3.8.9 query performance regression
on externals * fixed [issue
4580](http://subversion.tigris.org/issues/show_bug.cgi?id=4580): 'svn
-v st' on file externals reports '?' instead of user and revision
after 'svn up' #### Client-side and server-side bugfixes: * fix a
segfault with old style text delta #### Server-side bugfixes: * fsfs:
reduce memory allocation with Apache * mod_dav_svn: emit first log
items as soon as possible * mod_dav_svn: use LimitXMLRequestBody for
skel-encoded requests * mod_dav_svn: do not ignore skel parsing errors
* detect invalid svndiff data earlier * prevent possible repository
corruption on power/disk failures * fixed [issue
4577](http://subversion.tigris.org/issues/show_bug.cgi?id=4577): Read
error with nodes whose DELTA chain starts with a PLAIN rep * fixed
[issue
4531](http://subversion.tigris.org/issues/show_bug.cgi?id=4531):
server-side copy (over dav) is slow and uses too much memory ####
Bindings bugfixes: * swig: fix memory corruption in
svn_client_copy_source_t ### Developer-visible changes: #### General:
* avoid failing some tests on versions of Python with a very old
sqlite * fix Ruby tests so they don't use the users real configuration
#### Bindings: * swig-pl: fix some stack memory problems

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2015-3184-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2015-3187-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1247249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1289958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1289959"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/178157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9de6dbe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"subversion-1.8.15-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
