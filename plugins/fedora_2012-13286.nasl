#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-13286.
#

include("compat.inc");

if (description)
{
  script_id(62148);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:25:12 $");

  script_cve_id("CVE-2012-2186");
  script_xref(name:"FEDORA", value:"2012-13286");

  script_name(english:"Fedora 18 : asterisk-10.7.1-2.fc18 (2012-13286)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"fix build on s390 The Asterisk Development Team has announced security
releases for Certified Asterisk 1.8.11 and Asterisk 1.8 and 10. The
available security releases are released as versions 1.8.11-cert7,
1.8.15.1, 10.7.1, and 10.7.1-digiumphones.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 1.8.11-cert7, 1.8.15.1, 10.7.1, and
10.7.1-digiumphones resolve the following two issues :

  - A permission escalation vulnerability in Asterisk
    Manager Interface. This would potentially allow remote
    authenticated users the ability to execute commands on
    the system shell with the privileges of the user running
    the Asterisk application. Please note that the
    README-SERIOUSLY.bestpractices.txt file delivered with
    Asterisk has been updated due to this and other related
    vulnerabilities fixed in previous versions of Asterisk.

  - When an IAX2 call is made using the credentials of a
    peer defined in a dynamic Asterisk Realtime Architecture
    (ARA) backend, the ACL rules for that peer are not
    applied to the call attempt. This allows for a remote
    attacker who is aware of a peer's credentials to bypass
    the ACL rules set for that peer.

These issues and their resolutions are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2012-012 and AST-2012-013, which
were released at the same time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.11-cert7
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.15.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.7.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.7.1-digiumphones

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2012-012.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2012-01
      3.pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-012.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-013.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.15.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?956de3ad"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.7.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76287dad"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.7.1-digiumphones
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bf6a6b4"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.11-cert7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31164e5a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=853541"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/087348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33a1bbd2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"asterisk-10.7.1-2.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk");
}
