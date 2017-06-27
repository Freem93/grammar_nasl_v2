#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-573.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75080);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2145");

  script_name(english:"openSUSE Security Update : perl-Module-Signature (openSUSE-SU-2013:1178-1)");
  script_summary(english:"Check for the openSUSE-2013-573 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"perl-Module-Signature was updated to 0.73, fixing bugs and security
issues :

Security fix for code execution in signature checking :

  - fix for bnc#828010 (CVE-2013-2145)

  - Properly redo the previous fix using
    File::Spec->file_name_is_absolute.

  - [Changes for 0.72 - Wed Jun 5 23:19:02 CST 2013]

  - Only allow loading Digest::* from absolute paths in
    @INC, by ensuring they begin with \ or / characters.
    Contributed by: Florian Weimer (CVE-2013-2145)

  - [Changes for 0.71 - Tue Jun 4 18:24:10 CST 2013]

  - Constrain the user-specified digest name to /^\w+\d+$/.

  - Avoid loading Digest::* from relative paths in @INC.
    Contributed by: Florian Weimer (CVE-2013-2145)

  - [Changes for 0.70 - Thu Nov 29 01:45:54 CST 2012]

  - Don't check gpg version if gpg does not exist. This
    avoids unnecessary warnings during installation when gpg
    executable is not installed. Contributed by: Kenichi
    Ishigaki

  - [Changes for 0.69 - Fri Nov 2 23:04:19 CST 2012]

  - Support for gpg under these alternate names: gpg gpg2
    gnupg gnupg2 Contributed by: Michael Schwern"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828010"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-Module-Signature package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Module-Signature");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"perl-Module-Signature-0.73-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"perl-Module-Signature-0.73-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Module-Signature");
}
