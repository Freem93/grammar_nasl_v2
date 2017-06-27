#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3392.
#

include("compat.inc");

if (description)
{
  script_id(32103);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_cve_id("CVE-2008-1927");
  script_bugtraq_id(28928);
  script_xref(name:"FEDORA", value:"2008-3392");

  script_name(english:"Fedora 8 : perl-5.8.8-39.fc8 (2008-3392)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Apr 29 2008 Marcela Maslanova <mmaslano at
    redhat.com> - 4:5.8.8-39

    - perl-5.8.8-CVE-2008-1927.patch - buffer overflow, when
      using unicode characters in regexp

  - Wed Mar 19 2008 Marcela Maslanova <mmaslano at
    redhat.com> - 4:5.8.8-38

    - 434865 upgrade Test::Simple

    - turn off test on loading Dummy in More.t, can't find
      module (path problem?)

    - 238581: careless use of gethostbyname() in Socket.xs

    - Thu Mar 13 2008 Marcela Maslanova <mmaslano at
      redhat.com> - 4:5.8.8-37

    - update CGI, because of broken upload method #431774

    - Fri Feb 29 2008 Marcela Maslanova <mmaslano at
      redhat.com> - 4:5.8.8-36

    - remove conflicts perl-File-Temp. Use obsoletes.

    - Fri Feb 29 2008 Marcela Maslanova <mmaslano at
      redhat.com> - 4:5.8.8-35

    - upgrade Scalar::Util - possible fix for many bugs.
      Packages dependent on this module could work even with
      use of CPAN modules.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=443928"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009626.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3ee5289"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"perl-5.8.8-39.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
