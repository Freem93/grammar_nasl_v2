#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-17755.
#

include("compat.inc");

if (description)
{
  script_id(50672);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/20 21:13:53 $");

  script_cve_id("CVE-2010-3855");
  script_bugtraq_id(44214);
  script_xref(name:"FEDORA", value:"2010-17755");

  script_name(english:"Fedora 12 : freetype-2.3.11-7.fc12 (2010-17755)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Nov 15 2010 Marek Kasik <mkasik at redhat.com>
    2.3.11-7

    - Add freetype-2.3.11-CVE-2010-3855.patch (Protect
      against invalid `runcnt' values.)

  - Resolves: #651764

    - Mon Oct 4 2010 Marek Kasik <mkasik at redhat.com>
      2.3.11-6

    - Add freetype-2.3.11-CVE-2010-2805.patch (Fix
      comparison.)

  - Add freetype-2.3.11-CVE-2010-2806.patch (Protect against
    negative string_size. Fix comparison.)

  - Add freetype-2.3.11-CVE-2010-2808.patch (Check the total
    length of collected POST segments.)

  - Add freetype-2.3.11-CVE-2010-3311.patch (Don't seek
    behind end of stream.)

  - Resolves: #638522

    - Mon Oct 4 2010 Marek Kasik <mkasik at redhat.com>
      2.3.11-5

    - Add freetype-2.3.11-CVE-2010-1797.patch (Check stack
      after execution of operations too. Skip the
      evaluations of the values in decoder, if
      cff_decoder_parse_charstrings() returns any error.)

  - Resolves: #621627

    - Fri Oct 1 2010 Marek Kasik <mkasik at redhat.com>
      2.3.11-4

    - Add freetype-2.3.11-CVE-2010-2498.patch (Assure that
      `end_point' is not larger than `glyph->num_points')

  - Add freetype-2.3.11-CVE-2010-2499.patch (Check the
    buffer size during gathering PFB fragments)

  - Add freetype-2.3.11-CVE-2010-2500.patch (Use smaller
    threshold values for `width' and `height')

  - Add freetype-2.3.11-CVE-2010-2519.patch (Check `rlen'
    the length of fragment declared in the POST fragment
    header)

  - Add freetype-2.3.11-CVE-2010-2520.patch (Fix bounds
    check)

  - Add freetype-2.3.11-CVE-2010-2527.patch (Use precision
    for `%s' where appropriate to avoid buffer overflows)

  - Add freetype-2.3.11-CVE-2010-2541.patch (Avoid overflow
    when dealing with names of axes)

  - Resolves: #613299

    - Thu Dec 3 2009 Behdad Esfahbod <behdad at redhat.com>
      2.3.11-3

    - Add freetype-2.3.11-more-demos.patch

    - New demo programs ftmemchk, ftpatchk, and fttimer

    - Thu Dec 3 2009 Behdad Esfahbod <behdad at redhat.com>
      2.3.11-2

    - Second try. Drop upstreamed patches.

    - Thu Dec 3 2009 Behdad Esfahbod <behdad at redhat.com>
      2.3.11-1

    - 2.3.11

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=645275"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/051251.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2109caa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"freetype-2.3.11-7.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");
}
