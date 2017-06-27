#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-1517.
#

include("compat.inc");

if (description)
{
  script_id(35667);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:41:46 $");

  script_cve_id("CVE-2009-0478");
  script_bugtraq_id(33604);
  script_xref(name:"FEDORA", value:"2009-1517");

  script_name(english:"Fedora 9 : squid-3.0.STABLE13-1.fc9 (2009-1517)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Feb 5 2009 Jonathan Steffan <jsteffan at
    fedoraproject.org> - 7:3.0.STABLE13-1

    - upgrade to latest upstream

    - Thu Jan 29 2009 Henrik Nordstrom <henrik at
      henriknordstrom.net> - 7:3.0.STABLE12-1

    - upgrade to latest upstream

    - Fri Dec 19 2008 Henrik Nordstrom <henrik at
      henriknordstrom.net> - 7:3.0.STABLE10-3

    - actually include the upstream bugfixes in the build

    - Fri Dec 19 2008 Henrik Nordstrom <henrik at
      henriknordstrom.net> - 7:3.0.STABLE10-2

    - upstream bugfixes for cache corruption and access.log
      response size errors

    - Fri Oct 24 2008 Henrik Nordstrom <henrik at
      henriknordstrom.net> - 7:3.0.STABLE10-1

    - upgrade to latest upstream

    - change logrotate to move instead of copytruncate

    - disable coss support, not officially supported in 3.0

    - Fri Oct 3 2008 Jiri Skala <jskala at redhat.com> -
      7:3.0.STABLE7-2

    - Resolves: #463129 - optional config file

    - Resolves: #458593 - noisy init script

    - Resolves: #450352 - build.patch patches only generated
      files

    - Mon Jun 30 2008 Jiri Skala <jskala at redhat.com> -
      7:3.0.STABLE7-1

    - upgrade to latest upstream

    - fix CVE-2004-0918 Squid SNMP DoS [Fedora 9] (#453214)

    - Mon May 26 2008 Martin Nagy <mnagy at redhat.com> -
      7:3.0.STABLE6-1

    - upgrade to latest upstream

    - fix bad allocation (#447045)

    - Fri May 9 2008 Alexandre Oliva <aoliva at redhat.com>
      - 7:3.0.STABLE2-3

    - fix configure detection of netfilter kernel headers
      (#435499)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484246"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/020003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeb0d5db"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"squid-3.0.STABLE13-1.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
