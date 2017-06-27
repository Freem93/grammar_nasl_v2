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
  script_id(64469);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2012-6052", "CVE-2012-6053", "CVE-2012-6054", "CVE-2012-6055", "CVE-2012-6056", "CVE-2012-6057", "CVE-2012-6058", "CVE-2012-6059", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062");

  script_name(english:"SuSE 11.2 Security Update : wireshark (SAT Patch Number 7240)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to 1.8.4 fixes the following issues :

  - Wireshark could leak potentially sensitive host name
    resolution information when working with multiple
    pcap-ng files. (wnpa-sec-2012-30, CVE-2012-5592)

  - The USB dissector could go into an infinite loop.
    (wnpa-sec-2012-31, CVE-2012-5593)

  - The sFlow dissector could go into an infinite loop.
    (npa-sec-2012-32, CVE-2012-5594)

  - The SCTP dissector could go into an infinite loop.
    (wnpa-sec-2012-33, CVE-2012-5595)

  - The EIGRP dissector could go into an infinite loop.
    (wnpa-sec-2012-34, CVE-2012-5596)

  - The ISAKMP dissector could crash. (wnpa-sec-2012-35,
    CVE-2012-5597)

  - The iSCSI dissector could go into an infinite loop.
    (wnpa-sec-2012-36, CVE-2012-5598)

  - The WTP dissector could go into an infinite loop.
    (wnpa-sec-2012-37, CVE-2012-5599)

  - The RTCP dissector could go into an infinite loop.
    (wnpa-sec-2012-38, CVE-2012-5600)

  - The 3GPP2 A11 dissector could go into an infinite loop.
    (wnpa-sec-2012-39, CVE-2012-5601)

  - The ICMPv6 dissector could go into an infinite loop.
    (wnpa-sec-2012-40, CVE-2012-5602) Further bug fixes and
    updated protocol support as listed at
    http://www.wireshark.org/docs/relnotes/wireshark-1.8.4.h
    tml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5592.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5594.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5595.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5599.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5602.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7240.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"wireshark-1.8.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"wireshark-1.8.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"wireshark-1.8.4-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
