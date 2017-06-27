#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-2360.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52561);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-1147");
  script_bugtraq_id(46474);
  script_xref(name:"FEDORA", value:"2011-2360");

  script_name(english:"Fedora 15 : asterisk-1.8.3-1.fc15 (2011-2360)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced the release of Asterisk
1.8.3. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/ The release of
Asterisk 1.8.3 resolves several issues reported by the community and
would have not been possible without your participation. Thank you!
The following is a sample of the issues resolved in this release :

  - Resolve duplicated data in the AstDB when using
    DIALGROUP() (Closes issue #18091. Reported by bunny.
    Patched by tilghman)

  - Ensure the ipaddr field in realtime is large enough to
    handle IPv6 addresses. (Closes issue #18464. Reported,
    patched by IgorG)

  - Reworking parsing of mwi => lines to resolve a segfault.
    Also add a set of unit tests for the function that does
    the parsing. (Closes issue #18350. Reported by gbour.
    Patched by Marquis)

  - When using cdr_pgsql the billsec field was not populated
    correctly on unanswered calls. (Closes issue #18406.
    Reported by joscas. Patched by tilghman)

  - Resolve memory leak in iCalendar and Exchange
    calendaring modules. (Closes issue #18521. Reported,
    patched by pitel. Tested by cervajs)

  - This version of Asterisk includes the new Compiler Flags
    option BETTER_BACKTRACES which uses libbfd to search for
    better symbol information within both the Asterisk
    binary, as well as loaded modules, to assist when using
    inline backtraces to track down problems. (Patched by
    tilghman)

  - Resolve issue where no Music On Hold may be triggered
    when using res_timing_dahdi. (Closes issues #18262.
    Reported by francesco_r. Patched by cjacobson. Tested by
    francesco_r, rfrantik, one47)

  - Resolve a memory leak when the Asterisk Manager
    Interface is disabled. (Reported internally by kmorgan.
    Patched by russellb)

  - Reimplemented fax session reservation to reverse the ABI
    breakage introduced in r297486. (Reported internally.
    Patched by mnicholson)

  - Fix regression that changed behavior of queues when
    ringing a queue member. (Closes issue #18747, #18733.
    Reported by vrban. Patched by qwell.)

  - Resolve deadlock involving REFER. (Closes issue #18403.
    Reported, tested by jthurman. Patched by jpeeler.)
    Additionally, this release has the changes related to
    security bulletin AST-2011-002 which can be found at
    http://downloads.asterisk.org/pub/security/AST-2011-002.
    pdf For a full list of changes in this release, please
    see the ChangeLog:
    http://downloads.asterisk.org/pub/telephony/asterisk/Cha
    ngeLog-1.8.3

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-002.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.8.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=18747"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/055030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?704c4ace"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"asterisk-1.8.3-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk");
}
