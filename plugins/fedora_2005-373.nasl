#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-373.
#

include("compat.inc");

if (description)
{
  script_id(18337);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:38:04 $");

  script_cve_id("CVE-1999-0710", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-1519");
  script_xref(name:"FEDORA", value:"2005-373");

  script_name(english:"Fedora Core 3 : squid-2.5.STABLE9-1.FC3.6 (2005-373)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon May 16 2005 Jay Fenlason <fenlason at redhat.com>
    7:2.5.STABLE9-1.FC3.6

  - More upstream patches, including ones for bz#157456
    CVE-2005-1519 DNS lookups unreliable on untrusted
    networks bz#156162 CVE-1999-0710 cachemgr.cgi access
    control bypass

  - The following bugs had already been fixed, but the
    announcements were lost bz#156711 CVE-2005-1390 HTTP
    Request Smuggling Vulnerabilities bz#156703
    CVE-2005-1389 HTTP Response Splitting Vulnerabilities
    (Both fixed by squid-7:2.5.STABLE8-1.FC3.1) bz#151419
    Unexpected access control results on configuration
    errors (Fixed by 7:2.5.STABLE9-1.FC3.2)
    bz#152647#squid-2.5.STABLE9-1.FC3.4.x86_64.rpm is broken
    (fixed by 7:2.5.STABLE9-1.FC3.5) bz#141938 squid ldap
    authentification broken (Fixed by 7:2.5.STABLE7-1.FC3)

  - Fri Apr 1 2005 Jay Fenlason <fenlason at redhat.com>
    7:2.5.STABLE9-1.FC3.5

  - More upstream patches, including a new version of the
    -2GB patch that doesn't break diskd.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-May/000911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08f99907"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid and / or squid-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"squid-2.5.STABLE9-1.FC3.6")) flag++;
if (rpm_check(release:"FC3", reference:"squid-debuginfo-2.5.STABLE9-1.FC3.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo");
}
