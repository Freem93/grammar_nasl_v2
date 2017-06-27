#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64122);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:41:52 $");

  script_cve_id("CVE-2012-3570", "CVE-2012-3571", "CVE-2012-3954");

  script_name(english:"SuSE 11.2 Security Update : dhcp (SAT Patch Number 6606)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides dhcp 4.2.4-p1, which fixes the dhcpv6 server
crashing while accessing the lease on heap and provides the following
additional fixes :

  - Security fixes :

  - Previously the server code was relaxed to allow packets
    with zero length client ids to be processed. Under some
    situations use of zero length client ids can cause the
    server to go into an infinite loop. As such ids are not
    valid according to RFC 2132 section 9.14 the server no
    longer accepts them. Client ids with a length of 1 are
    also invalid but the server still accepts them in order
    to minimize disruption. The restriction will likely be
    tightened in the future to disallow ids with a length of
    1. (ISC-Bugs #29851, CVE-2012-3571)

  - When attempting to convert a DUID from a client id
    option into a hardware address handle unexpected client
    ids properly. (ISC-Bugs #29852, CVE-2012-3570)

  - A pair of memory leaks were found and fixed. (ISC-Bugs
    #30024, (CVE-2012-3954) )

  - Further upstream fixes :

  - Moved lease file check to a separate action so it is not
    used in restart -- it can fail when the daemon rewrites
    the lease causing a restart failure then.

  - Request dhcp6.sntp-servers in /etc/dhclient6.conf and
    forward to netconfig for processing.

  - Rotate the lease file when running in v6 mode. (ISC-Bugs
    #24887)

  - Fixed the code that checks if an address the server is
    planning to hand out is in a reserved range. This would
    appear as the server being out of addresses in pools
    with particular ranges. (ISC-Bugs #26498)

  - In the DDNS code handle error conditions more gracefully
    and add more logging code. The major change is to handle
    unexpected cancel events from the DNS client code.
    (ISC-Bugs #26287)

  - Tidy up the receive calls and eliminate the need for
    found_pkt. (ISC-Bugs #25066)

  - Add support for Infiniband over sockets to the server
    and relay code.

  - Modify the code that determines if an outstanding DDNS
    request should be cancelled. This patch results in
    cancelling the outstanding request less often. It fixes
    the problem caused by a client doing a release where the
    TXT and PTR records weren't removed from the DNS.
    (ISC-BUGS #27858)

  - Remove outdated note in the description of the bootp
    keyword about the option not satisfying the requirement
    of failover peers for denying dynamic bootp clients.
    (ISC-bugs #28574)

  - Multiple items to clean up IPv6 address processing. When
    processing an IA that we've seen check to see if the
    addresses are usable (not in use by somebody else)
    before handing it out. When reading in leases from the
    file discard expired addresses. When picking an address
    for a client include the IA ID in addition to the client
    ID to generally pick different addresses for different
    IAs. (ISC-Bugs #23138, #27945, #25586, #27684)

  - Remove unnecessary checks in the lease query code and
    clean up several compiler issues (some dereferences of
    NULL and treating an int as a boolean). (ISC-Bugs
    #26203)

  - Fix the NA and PD allocation code to handle the case
    where a client provides a preference and the server
    doesn't have any addresses or prefixes available.
    Previoulsy the server ignored the request with this
    patch it replies with a NoAddrsAvail or NoPrefixAvail
    response. By default the code performs according to the
    errata of August 2010 for RFC 3315 section 17.2.2; to
    enable the previous style see the section on
    RFC3315_PRE_ERRATA_2010_08 in includes/site.h.

  - Fix up some issues found by static analysis. A potential
    memory leak and NULL dereference in omapi. The use of a
    boolean test instead of a bitwise test in dst. (ISC-Bugs
    #28941)

In addition, the dhcp-server init script now checks the syntax prior
restarting the daemon to avoid stopping of the daemon when a start
would fail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3954.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6606.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"dhcp-4.2.4.P1-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"dhcp-client-4.2.4.P1-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"dhcp-4.2.4.P1-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"dhcp-client-4.2.4.P1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"dhcp-4.2.4.P1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"dhcp-client-4.2.4.P1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"dhcp-relay-4.2.4.P1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"dhcp-server-4.2.4.P1-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
