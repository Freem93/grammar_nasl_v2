#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-11469.
#

include("compat.inc");

if (description)
{
  script_id(85059);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:49:05 $");

  script_cve_id("CVE-2015-5381", "CVE-2015-5382", "CVE-2015-5383");
  script_xref(name:"FEDORA", value:"2015-11469");

  script_name(english:"Fedora 21 : roundcubemail-1.1.2-1.fc21 (2015-11469)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Release 1.1.2**

  - Add new plugin hook 'identity_create_after' providing
    the ID of the inserted identity (#1490358)

    - Add option to place signature at bottom of the quoted
      text even in top-posting mode [sig_below]

    - Fix handling of %-encoded entities in mailto: URLs
      (#1490346)

    - Fix zipped messages downloads after selecting all
      messages in a folder (#1490339)

    - Fix vpopmaild driver of password plugin

    - Fix PHP warning: Non-static method
      PEAR::setErrorHandling() should not be called
      statically (#1490343)

    - Fix tables listing routine on mysql and postgres so it
      skips system or other database tables and views
      (#1490337)

    - Fix message list header in classic skin on window
      resize in Internet Explorer (#1490213)

    - Fix so text/calendar parts are listed as attachments
      even if not marked as such (#1490325)

    - Fix lack of signature separator for plain text
      signatures in html mode (#1490352)

    - Fix font artifact in Google Chrome on Windows
      (#1490353)

    - Fix bug where forced extwin page reload could exit
      from the extwin mode (#1490350)

    - Fix bug where some unrelated attachments in
      multipart/related message were not listed (#1490355)

    - Fix mouseup event handling when dragging a list record
      (#1490359)

    - Fix bug where preview_pane setting wasn't always saved
      into user preferences (#1490362)

    - Fix bug where messages count was not updated after
      message move/delete with skip_deleted=false (#1490372)

    - Fix security issue in contact photo handling
      (#1490379)

    - Fix possible memcache/apc cache data consistency
      issues (#1490390)

    - Fix bug where imap_conn_options were ignored in IMAP
      connection test (#1490392)

    - Fix bug where some files could have 'executable'
      extension when stored in temp folder (#1490377)

    - Fix attached file path unsetting in
      database_attachments plugin (#1490393)

    - Fix issues when using moduserprefs.sh without --user
      argument (#1490399)

    - Fix potential info disclosure issue by protecting
      directory access (#1490378)

    - Fix blank image in html_signature when saving identity
      changes (#1490412)

    - Installer: Use openssl_random_pseudo_bytes() (if
      available) to generate des_key (#1490402)

    - Fix XSS vulnerability in _mbox argument handling
      (#1490417)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241056"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162542.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54a7dfdf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/29");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"roundcubemail-1.1.2-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
