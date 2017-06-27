#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-eb896290d3.
#

include("compat.inc");

if (description)
{
  script_id(89447);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/03/20 04:41:30 $");

  script_cve_id("CVE-2015-8383", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8393", "CVE-2015-8394");
  script_xref(name:"FEDORA", value:"2015-eb896290d3");

  script_name(english:"Fedora 22 : pcre-8.38-1.fc22 (2015-eb896290d3)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release fixes these vulnerabilies: CVE-2015-8383, CVE-2015-8386,
CVE-2015-8387, CVE-2015-8389, CVE-2015-8390, CVE-2015-8391,
CVE-2015-8393, CVE-2015-8394. It also fixes compiling comments with
auto-callouts, compiling expressions with negated classes in UCP mode,
compiling expressions with an isolated \E between an item and its
qualifier with auto-callouts, a crash in regexec() if REG_STARTEND
option is set and pmatch argument is NULL, a stack overflow when
formatting a 32-bit integer in pcregrep tool, compiling expressions
with an empty \Q\E sequence between an item and its qualifier with
auto-callouts, compiling expressions with global extended modifier
that is disabled by local no-extended option at the start of the
expression just after a whitespace, a possible crash in
pcre_copy_named_substring() if a named substring has number greater
than the space in the ovector, a buffer overflow when compiling an
expression with named groups with a group that reset capture numbers,
and a crash in pcre_get_substring_list() if the use of \K caused the
start of the match to be earlier than the end.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1287702"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-January/174931.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e94c61f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcre package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pcre");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/04");
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
if (rpm_check(release:"FC22", reference:"pcre-8.38-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcre");
}
