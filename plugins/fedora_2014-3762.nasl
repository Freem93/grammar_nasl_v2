#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-3762.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73141);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/19 22:32:17 $");

  script_cve_id("CVE-2014-2286", "CVE-2014-2287", "CVE-2014-2288", "CVE-2014-2289");
  script_bugtraq_id(66093, 66094);
  script_xref(name:"FEDORA", value:"2014-3762");

  script_name(english:"Fedora 20 : asterisk-11.8.1-1.fc20 (2014-3762)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced security releases for
Certified Asterisk 1.8.15, 11.6, and Asterisk 1.8, 11, and 12. The
available security releases are released as versions 1.8.15-cert5,
11.6-cert2, 1.8.26.1, 11.8.1, and 12.1.1.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of these versions resolve the following issues :

  - AST-2014-001: Stack overflow in HTTP processing of
    Cookie headers.

    Sending a HTTP request that is handled by Asterisk with
    a large number of Cookie headers could overflow the
    stack.

    Another vulnerability along similar lines is any HTTP
    request with a ridiculous number of headers in the
    request could exhaust system memory.

  - AST-2014-002: chan_sip: Exit early on bad session timers
    request

    This change allows chan_sip to avoid creation of the
    channel and consumption of associated file descriptors
    altogether if the inbound request is going to be
    rejected anyway.

Additionally, the release of 12.1.1 resolves the following issue :

  - AST-2014-003: res_pjsip: When handling 401/407 responses
    don't assume a request will have an endpoint.

    This change removes the assumption that an outgoing
    request will always have an endpoint and makes the
    authenticate_qualify option work once again.

Finally, a security advisory, AST-2014-004, was released for a
vulnerability fixed in Asterisk 12.1.0. Users of Asterisk 12.0.0 are
encouraged to upgrade to 12.1.1 to resolve both vulnerabilities.

These issues and their resolutions are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2014-001, AST-2014-002,
AST-2014-003, and AST-2014-004, which were released at the same time
as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.15-cert5
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.26.1
http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-11.6-cert2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-11.8.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-12.1.1

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2014-001.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2014-00
      2.pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2014-00
      3.pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2014-00
      4.pdf The Asterisk Development Team has announced the
      release of Asterisk 11.8.0. This release is available
      for immediate download at
      http://downloads.asterisk.org/pub/telephony/asterisk

The release of Asterisk 11.8.0 resolves several issues reported by the
community and would have not been possible without your participation.
Thank you!

The following are the issues resolved in this release :

Bugs fixed in this release :

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-001.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-002.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-003.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-004.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.26.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68336dff"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.8.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbb290c2"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-12.1.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a9e33d8"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.15-cert5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d221303"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-11.6-cert2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd1dec6c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1074825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1074827"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-March/130426.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52b913c8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"asterisk-11.8.1-1.fc20")) flag++;


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
