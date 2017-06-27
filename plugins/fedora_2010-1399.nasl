#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-1399.
#

include("compat.inc");

if (description)
{
  script_id(47254);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:13:51 $");

  script_cve_id("CVE-2010-0464");
  script_xref(name:"FEDORA", value:"2010-1399");

  script_name(english:"Fedora 11 : roundcubemail-0.3.1-2.fc11 (2010-1399)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Common Vulnerabilities and Exposures assigned an identifier
CVE-2010-0464 to the following vulnerability: Name: CVE-2010-0464 URL:
http://cve.mitre.org /cgi-bin/cvename.cgi?name=CVE-2010-0464 Assigned:
20100129 Reference: MISC:
https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_W
ebmail Reference: CONFIRM: http://trac.roundcube.net/ticket/1486449
Roundcube 0.3.1 and earlier does not request that the web browser
avoid DNS prefetching of domain names contained in e-mail messages,
which makes it easier for remote attackers to determine the network
location of the webmail user by logging DNS requests.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/ticket/1486449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=560142"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/034685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d183b34"
  );
  # https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_Webmail
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7dd89e9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"roundcubemail-0.3.1-2.fc11")) flag++;


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
