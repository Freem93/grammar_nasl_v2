#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-8678.
#

include("compat.inc");

if (description)
{
  script_id(34357);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:23:17 $");

  script_cve_id("CVE-2008-4408");
  script_bugtraq_id(31540);
  script_xref(name:"FEDORA", value:"2008-8678");

  script_name(english:"Fedora 8 : mediawiki-1.13.2-40.99.fc8 (2008-8678)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Sun Oct 5 2008 Axel Thimm <Axel.Thimm at ATrpms.net> -
    1.13.2-40.99

    - Update to 1.13.2.

    - Fedora 8 still needs ugly workaround.

    - Sun Aug 24 2008 Axel Thimm <Axel.Thimm at ATrpms.net>
      - 1.13.0-40

    - Use consistently Patch0 and %patch0.

    - Sat Aug 16 2008 Axel Thimm <Axel.Thimm at ATrpms.net>
      - 1.13.0-39

    - Update to 1.13.0.

    - Wed May 21 2008 Tom 'spot' Callaway <tcallawa at
      redhat.com> 1.10.4-40

    - fix license tag

    - Tue Mar 4 2008 Axel Thimm <Axel.Thimm at ATrpms.net> -
      1.10.4-38

    - Update to 1.10.4.

    - Sun Feb 17 2008 Axel Thimm <Axel.Thimm at ATrpms.net>
      - 1.10.3-37

    - Update to 1.10.3.

    - Fixes CVE-2008-0460 (bug #430286).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=465734"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-October/015160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bcb5ee1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC8", reference:"mediawiki-1.13.2-40.99.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}
