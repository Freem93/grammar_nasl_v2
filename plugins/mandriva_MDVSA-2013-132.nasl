#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:132. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66144);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2011-2768", "CVE-2011-2769", "CVE-2012-3517", "CVE-2012-3518", "CVE-2012-3519", "CVE-2012-4419", "CVE-2012-5573");
  script_bugtraq_id(50414, 55128, 55519, 56675);
  script_xref(name:"MDVSA", value:"2013:132");
  script_xref(name:"MGASA", value:"2012-0276");
  script_xref(name:"MGASA", value:"2012-0356");

  script_name(english:"Mandriva Linux Security Advisory : tor (MDVSA-2013:132)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tor package fixes security vulnerabilities :

Tor before 0.2.2.34, when configured as a client or bridge, sends a
TLS certificate chain as part of an outgoing OR connection, which
allows remote relays to bypass intended anonymity properties by
reading this chain and then determining the set of entry guards that
the client or bridge had selected (CVE-2011-2768).

Tor before 0.2.2.34, when configured as a bridge, accepts the CREATE
and CREATE_FAST values in the Command field of a cell within an OR
connection that it initiated, which allows remote relays to enumerate
bridges by using these values (CVE-2011-2769).

Use-after-free vulnerability in dns.c in Tor before 0.2.2.38 might
allow remote attackers to cause a denial of service (daemon crash) via
vectors related to failed DNS requests (CVE-2012-3517).

The networkstatus_parse_vote_from_string function in routerparse.c in
Tor before 0.2.2.38 does not properly handle an invalid flavor name,
which allows remote attackers to cause a denial of service
(out-of-bounds read and daemon crash) via a crafted (1) vote document
or (2) consensus document (CVE-2012-3518).

routerlist.c in Tor before 0.2.2.38 uses a different amount of time
for relay-list iteration depending on which relay is chosen, which
might allow remote attackers to obtain sensitive information about
relay selection via a timing side-channel attack (CVE-2012-3519).

The compare_tor_addr_to_addr_policy function in or/policies.c in Tor
before 0.2.2.39, and 0.2.3.x before 0.2.3.21-rc, allows remote
attackers to cause a denial of service (assertion failure and daemon
exit) via a zero-valued port field that is not properly handled during
policy comparison (CVE-2012-4419).

Tor before 0.2.2.39, when waiting for a client to renegotiate, allowed
it to add bytes to the input buffer, allowing a crash to be caused
remotely (tor-5934, tor-6007).

Denial of Service vulnerability in Tor before 0.2.3.25, due to an
error when handling SENDME cells and can be exploited to cause
excessive consumption of memory resources within an entry node
(SA51329, CVE-2012-5573).

The version of Tor shipped in MBS1 did not have correctly formed
systemd unit and thus failed to start.

This updated version corrects this problem and restores working
behaviour."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.mageia.org/en/Support/Advisories/MGAA-2012-0184"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tor-0.2.2.39-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
