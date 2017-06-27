#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-2438.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52602);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-1147");
  script_bugtraq_id(46474);
  script_xref(name:"FEDORA", value:"2011-2438");

  script_name(english:"Fedora 14 : asterisk-1.6.2.17-1.fc14 (2011-2438)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced the release of Asterisk
1.6.2.17. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/ The release of
Asterisk 1.6.2.17 resolves several issues reported by the community
and would have not been possible without your participation. Thank
you! The following is a sample of the issues resolved in this 
release :

  - Resolve duplicated data in the AstDB when using
    DIALGROUP() (Closes issue #18091. Reported by bunny.
    Patched by tilghman)

  - Correct issue where res_config_odbc could populate
    fields with invalid data. (Closes issue #18251, #18279.
    Reported by bcnit, zerohalo. Tested by trev, jthurman,
    elguero, zerohalo. Patched by tilghman)

  - When using cdr_pgsql the billsec field was not populated
    correctly on unanswered calls. (Closes issue #18406.
    Reported by joscas. Patched by tilghman)

  - Resolve issue where re-transmissions of SUBSCRIBE could
    break presence. (Closes issue #18075. Reported by
    mdu113. Patched by twilson)

  - Fix regression causing forwarding voicemails to not work
    with file storage. (Closes issue #18358. Reported by
    cabal95. Patched by jpeeler)

  - This version of Asterisk includes the new Compiler Flags
    option BETTER_BACKTRACES which uses libbfd to search for
    better symbol information within both the Asterisk
    binary, as well as loaded modules, to assist when using
    inline backtraces to track down problems. (Patched by
    tilghman)

  - Resolve several issues with DTMF based attended
    transfers. (Closes issues #17999, #17096, #18395,
    #17273. Reported by iskatel, gelo, shihchaun, grecco.
    Patched by rmudgett). NOTE: Be sure to read the
    ChangeLog for more information about these changes.

  - Resolve issue where no Music On Hold may be triggered
    when using res_timing_dahdi. (Closes issues #18262.
    Reported by francesco_r. Patched by cjacobson. Tested by
    francesco_r, rfrantik, one47)

  - Fix regression that changed behavior of queues when
    ringing a queue member. (Closes issue #18747, #18733.
    Reported by vrban. Patched by qwell.) Additionally, this
    release has the changes related to security bulletin
    AST-2011-002 which can be found at
    http://downloads.asterisk.org/pub/security/AST-2011-002.
    pdf For a full list of changes in this release, please
    see the ChangeLog:
    http://downloads.asterisk.org/pub/telephony/asterisk/Cha
    ngeLog-1.6.2.17 Asterisk Project Security Advisory -
    AST-2011-002 Product Asterisk Summary Multiple array
    overflow and crash vulnerabilities in UDPTL code Nature
    of Advisory Exploitable Stack and Heap Array Overflows
    Susceptibility Remote Unauthenticated Sessions Severity
    Critical Exploits Known No Reported On January 27, 2011
    Reported By Matthew Nicholson Posted On February 21,
    2011 Last Updated On February 21, 2011 Advisory Contact
    Matthew Nicholson <mnicholson at digium.com> CVE Name
    Description When decoding UDPTL packets, multiple stack
    and heap based arrays can be made to overflow by
    specially crafted packets. Systems doing T.38 pass
    through or termination are vulnerable. Resolution The
    UDPTL decoding routines have been modified to respect
    the limits of exploitable arrays. In asterisk versions
    not containing the fix for this issue, disabling T.38
    support will prevent this vulnerability from being
    exploited. T.38 support can be disabled in chan_sip by
    setting the t38pt_udptl option to 'no' (it is off by
    default). t38pt_udptl = no The chan_ooh323 module should
    also be disabled by adding the following line in
    modles.conf. noload => chan_ooh323 Affected Versions
    Product Release Series Asterisk Open Source 1.4.x All
    versions Asterisk Open Source 1.6.x All versions
    Asterisk Business Edition C.x.x All versions AsteriskNOW
    1.5 All versions s800i (Asterisk Appliance) 1.2.x All
    versions Corrected In Product Release Asterisk Open
    Source 1.4.39.2, 1.6.1.22, 1.6.2.16.2, 1.8.2.4 Asterisk
    Business Edition C.3.6.3 Patches URL Branch
    http://downloads.asterisk.org/pub/security/AST-2011-002-
    1.4.diff 1.4
    http://downloads.asterisk.org/pub/security/AST-2011-002-
    1.6.1.diff 1.6.1
    http://downloads.asterisk.org/pub/security/AST-2011-002-
    1.6.2.diff 1.6.2
    http://downloads.asterisk.org/pub/security/AST-2011-002-
    1.8.diff 1.8 Links Asterisk Project Security Advisories
    are posted at http://www.asterisk.org/security This
    document may be superseded by later versions; if so, the
    latest version will be posted at
    http://downloads.digium.com/pub/security/AST-2011-002.pd
    f and
    http://downloads.digium.com/pub/security/AST-2011-002.ht
    ml Revision History Date Editor Revisions Made 02/21/11
    Matthew Nicholson Initial Release Asterisk Project
    Security Advisory - AST-2011-002 Copyright (c) 2011
    Digium, Inc. All Rights Reserved. Permission is hereby
    granted to distribute and publish this advisory in its
    original, unaltered form.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-002-1.4.diff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-002-1.6.1.diff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-002-1.6.2.diff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-002-1.8.diff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-002.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.6.2.17
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21150610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.digium.com/pub/security/AST-2011-002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.digium.com/pub/security/AST-2011-002.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.asterisk.org/security"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/055421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a9fa273"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"asterisk-1.6.2.17-1.fc14")) flag++;


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
