#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-afdb0e8aaa.
#

include("compat.inc");

if (description)
{
  script_id(89372);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/18 16:42:53 $");

  script_cve_id("CVE-2015-5259", "CVE-2015-5343");
  script_xref(name:"FEDORA", value:"2015-afdb0e8aaa");

  script_name(english:"Fedora 23 : subversion-1.9.3-1.fc23 (2015-afdb0e8aaa)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of _Apache Subversion_,
version **1.9.3**. ### User-visible changes: #### Client-side
bugfixes: * svn: fix possible crash in auth credentials cache *
cleanup: avoid unneeded memory growth during pristine cleanup * diff:
fix crash when repository is on server root * fix translations for
commit notifications * ra_serf: fix crash in multistatus parser * svn:
report lock/unlock errors as failures * svn: cleanup user deleted
external registrations * svn: allow simple resolving of binary file
text conflicts * svnlook: properly remove tempfiles on diff errors *
ra_serf: report built- and run-time versions of libserf * ra_serf: set
Content- Type header in outgoing requests * svn: fix merging deletes
of svn:eol-style CRLF/CR files * ra_local: disable zero-copy code path
#### Server-side bugfixes: * mod_authz_svn: fix authz with
mod_auth_kerb/mod_auth_ntlm ( [issue
4602](http://subversion.tigris.org/issues/show_bug.cgi?id=4602)) *
mod_dav_svn: fix display of process ID in cache statistics *
mod_dav_svn: use LimitXMLRequestBody for skel-encoded requests *
svnadmin dump: preserve no-op changes * fsfs: avoid unneeded I/O when
opening transactions #### Bindings bugfixes: * javahl: fix ABI
incompatibility with 1.8 * javahl: allow non- absolute paths in
SVNClient.vacuum ### Developer-visible changes: #### General :

  - fix patch filter invocation in svn_client_patch() * add
    \@since information to config defines * fix running the
    tests in compatibility mode * clarify documentation of
    svn_fs_node_created_rev() #### API changes: * fix
    overflow detection in svn_stringbuf_remove and _replace
    * don't ignore some of the parameters to
    svn_ra_svn_create_conn3

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/issues/show_bug.cgi?id=4602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1289958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1289959"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2163ff8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/22");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"subversion-1.9.3-1.fc23")) flag++;


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
