#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-8670.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59434);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:36:31 $");

  script_cve_id("CVE-2012-2947");
  script_bugtraq_id(53722);
  script_xref(name:"FEDORA", value:"2012-8670");

  script_name(english:"Fedora 17 : asterisk-10.4.2-1.fc17 (2012-8670)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"he Asterisk Development Team has announced the release of Asterisk
10.4.2. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk

The release of Asterisk 10.4.2 resolves several issues reported by the
community and would have not been possible without your participation.
Thank you!

The following are the issues resolved in this release :

  - --- Resolve crash in subscribing for MWI notifications
    (Closes issue ASTERISK-19827. Reported by B. R)

  - --- Fix crash in ConfBridge when user announcement is
    played for more than 2 users (Closes issue
    ASTERISK-19899. Reported by Florian Gilcher)

For a full list of changes in this release, please see the ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-10.4.2

The Asterisk Development Team has announced security releases for
Certified Asterisk 1.8.11 and Asterisk 1.8 and 10. The available
security releases are released as versions 1.8.11-cert2, 1.8.12.1, and
10.4.1.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 1.8.11-cert2, 1.8.12.1, and 10.4.1 resolve the
following two issues :

  - A remotely exploitable crash vulnerability exists in the
    IAX2 channel driver if an established call is placed on
    hold without a suggested music class. Asterisk will
    attempt to use an invalid pointer to the music on hold
    class name, potentially causing a crash.

  - A remotely exploitable crash vulnerability was found in
    the Skinny (SCCP) Channel driver. When an SCCP client
    closes its connection to the server, a pointer in a
    structure is set to NULL. If the client was not in the
    on-hook state at the time the connection was closed,
    this pointer is later dereferenced. This allows remote
    authenticated connections the ability to cause a crash
    in the server, denying services to legitimate users.

These issues and their resolution are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2012-007 and AST-2012-008, which
were released at the same time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.11-cert2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.12.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.4.1

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2012-007.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2012-00
      8.pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-007.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-008.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-10.4.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.12.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01547647"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.4.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ef88683"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.11-cert2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f897510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=826474"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-June/082077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7abb49b6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"asterisk-10.4.2-1.fc17")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk");
}
