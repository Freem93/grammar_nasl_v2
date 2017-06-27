#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-5948.
#

include("compat.inc");

if (description)
{
  script_id(84910);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/02/14 05:40:10 $");

  script_cve_id("CVE-2015-3008");
  script_xref(name:"FEDORA", value:"2015-5948");

  script_name(english:"Fedora 22 : asterisk-13.3.2-1.fc22 (2015-5948)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced security releases for
Certified Asterisk 1.8.28, 11.6, and 13.1 and Asterisk 1.8, 11, 12,
and 13. The available security releases are released as versions
1.8.28.cert-5, 1.8.32.3, 11.6-cert11, 11.17.1, 12.8.2, 13.1-cert2, and
13.3.2.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of these versions resolves the following security
vulnerability :

  - AST-2015-003: TLS Certificate Common name NULL byte
    exploit

    When Asterisk registers to a SIP TLS device and and
    verifies the server, Asterisk will accept signed
    certificates that match a common name other than the one
    Asterisk is expecting if the signed certificate has a
    common name containing a null byte after the portion of
    the common name that Asterisk expected. This potentially
    allows for a man in the middle attack.

For more information about the details of this vulnerability, please
read security advisory AST-2015-003, which was released at the same
time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.28-cert5
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.32.3
http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-11.6-cert11
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-11.17.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-12.8.2
http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-13.1-cert2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-13.3.2

The security advisory is available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2015-003.
    pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2015-003.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.32.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85da8028"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.17.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f7655dc"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-12.8.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e407efd"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-13.3.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aaf19503"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.28-cert5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f561735"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-11.6-cert11
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de0a6932"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-13.1-cert2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3362af83"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1210225"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab88120f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC22", reference:"asterisk-13.3.2-1.fc22")) flag++;


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
