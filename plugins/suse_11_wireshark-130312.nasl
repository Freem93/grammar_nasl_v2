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
  script_id(66254);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2013-2475", "CVE-2013-2476", "CVE-2013-2477", "CVE-2013-2478", "CVE-2013-2479", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482", "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2486", "CVE-2013-2487", "CVE-2013-2488");

  script_name(english:"SuSE 11.2 Security Update : wireshark (SAT Patch Number 7490)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wireshark has been updated to 1.8.6 which fixes bugs and security
issues :

Vulnerabilities fixed :

  - The TCP dissector could crash. wnpa-sec-2013-10.
    (CVE-2013-2475)

  - The HART/IP dissectory could go into an infinite loop.
    wnpa-sec-2013-11. (CVE-2013-2476)

  - The CSN.1 dissector could crash. wnpa-sec-2013-12.
    (CVE-2013-2477)

  - The MS-MMS dissector could crash. wnpa-sec-2013-13.
    (CVE-2013-2478)

  - The MPLS Echo dissector could go into an infinite loop.
    wnpa-sec-2013-14. (CVE-2013-2479)

  - The RTPS and RTPS2 dissectors could crash.
    wnpa-sec-2013-15. (CVE-2013-2480)

  - The Mount dissector could crash. wnpa-sec-2013-16.
    (CVE-2013-2481)

  - The AMPQ dissector could go into an infinite loop.
    wnpa-sec-2013-17. (CVE-2013-2482)

  - The ACN dissector could attempt to divide by zero.
    wnpa-sec-2013-18. (CVE-2013-2483)

  - The CIMD dissector could crash. wnpa-sec-2013-19.
    (CVE-2013-2484)

  - The FCSP dissector could go into an infinite loop.
    wnpa-sec-2013-20. (CVE-2013-2485)

  - The RELOAD dissector could go into an infinite loop.
    wnpa-sec-2013-21. (CVE-2013-2486 / CVE-2013-2487)

  - The DTLS dissector could crash. wnpa-sec-2013-22
    (CVE-2013-2488) More information about further bug fixes
    and updated protocol support are listed here:
    http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.h
    tml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2488.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7490.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/29");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"wireshark-1.8.6-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"wireshark-1.8.6-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"wireshark-1.8.6-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
