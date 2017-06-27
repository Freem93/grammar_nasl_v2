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
  script_id(69091);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/13 15:30:42 $");

  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562", "CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077", "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081", "CVE-2013-4082", "CVE-2013-4083");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : wireshark (SAT Patch Numbers 8044 / 8045)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This wireshark version update to 1.8.8 includes several security and
general bug fixes.

Version update to 1.8.8 [bnc#824900] :

  - vulnerabilities fixed :

  - The CAPWAP dissector could crash. wnpa-sec-2013-32.
    (CVE-2013-4074)

  - The GMR-1 BCCH dissector could crash. wnpa-sec-2013-33.
    (CVE-2013-4075)

  - The PPP dissector could crash. wnpa-sec-2013-34.
    (CVE-2013-4076)

  - The NBAP dissector could crash. wnpa-sec-2013-35.
    (CVE-2013-4077)

  - The RDP dissector could crash. wnpa-sec-2013-36.
    (CVE-2013-4078)

  - The GSM CBCH dissector could crash. wnpa-sec-2013-37.
    (CVE-2013-4079)

  - The Assa Abloy R3 dissector could consume excessive
    memory and CPU. wnpa-sec-2013-38. (CVE-2013-4080)

  - The HTTP dissector could overrun the stack.
    wnpa-sec-2013-39. (CVE-2013-4081)

  - The Ixia IxVeriWave file parser could overflow the heap.
    wnpa-sec-2013-40. (CVE-2013-4082)

  - The DCP ETSI dissector could crash. wnpa-sec-2013-41.
    (CVE-2013-4083)

  - Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.8.8.
    html Version update to 1.8.7 [bnc#813217, bnc#820973] :

  - vulnerabilities fixed :

  - The RELOAD dissector could go into an infinite loop.
    wnpa-sec-2013-23. (CVE-2013-2486 / CVE-2013-2487)

  - The GTPv2 dissector could crash. wnpa-sec-2013-24

  - The ASN.1 BER dissector could crash. wnpa-sec-2013-25

  - The PPP CCP dissector could crash. wnpa-sec-2013-26

  - The DCP ETSI dissector could crash. wnpa-sec-2013-27

  - The MPEG DSM-CC dissector could crash. wnpa-sec-2013-28

  - The Websocket dissector could crash. wnpa-sec-2013-29

  - The MySQL dissector could go into an infinite loop.
    wnpa-sec-2013-30

  - The ETCH dissector could go into a large loop.
    wnpa-sec-2013-31

  - Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.8.7.
    html Ohter bug fixes :

  - 'Save As' Nokia libpcap corrupting the file.
    (bnc#816517)

  - wireshark crashed in 'SCTP' -> 'Prepare Filter for this
    Association'. (bnc#816887)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824900"
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
    value:"http://support.novell.com/security/cve/CVE-2013-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3560.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3561.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4082.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4083.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8044 / 8045 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"wireshark-1.8.8-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"wireshark-1.8.8-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"wireshark-1.8.8-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"wireshark-1.8.8-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"wireshark-1.8.8-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"wireshark-1.8.8-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
