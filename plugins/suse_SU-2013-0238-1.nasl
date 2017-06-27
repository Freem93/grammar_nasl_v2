#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0238-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83573);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-5592", "CVE-2012-5593", "CVE-2012-5594", "CVE-2012-5595", "CVE-2012-5596", "CVE-2012-5597", "CVE-2012-5598", "CVE-2012-5599", "CVE-2012-5600", "CVE-2012-5601", "CVE-2012-5602");
  script_bugtraq_id(56729);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : wireshark (SUSE-SU-2013:0238-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to 1.8.4 fixes the following issues :

  - Wireshark could leak potentially sensitive host name
    resolution information when working with multiple
    pcap-ng files. (wnpa-sec-2012-30, CVE-2012-5592 )

  - The USB dissector could go into an infinite loop.
    (wnpa-sec-2012-31, CVE-2012-5593 )

  - The sFlow dissector could go into an infinite loop.
    (npa-sec-2012-32, CVE-2012-5594 )

  - The SCTP dissector could go into an infinite loop.
    (wnpa-sec-2012-33, CVE-2012-5595 )

  - The EIGRP dissector could go into an infinite loop.
    (wnpa-sec-2012-34, CVE-2012-5596 )

  - The ISAKMP dissector could crash. (wnpa-sec-2012-35,
    CVE-2012-5597 )

  - The iSCSI dissector could go into an infinite loop.
    (wnpa-sec-2012-36, CVE-2012-5598 )

  - The WTP dissector could go into an infinite loop.
    (wnpa-sec-2012-37, CVE-2012-5599 )

  - The RTCP dissector could go into an infinite loop.
    (wnpa-sec-2012-38, CVE-2012-5600 )

  - The 3GPP2 A11 dissector could go into an infinite loop.
    (wnpa-sec-2012-39, CVE-2012-5601 )

  - The ICMPv6 dissector could go into an infinite loop.
    (wnpa-sec-2012-40, CVE-2012-5602 )

Further bug fixes and updated protocol support as listed at
http://www.wireshark.org/docs/relnotes/wireshark-1.8.4.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5602"
  );
  # http://download.suse.com/patch/finder/?keywords=5ca5c5a9d5146cf9db535109cf9e12c5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?339a0d86"
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
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.4.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/792005"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130238-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8fdfe40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP2 :

zypper in -t patch sdksp2-wireshark-7240

SUSE Linux Enterprise Server 11 SP2 for VMware :

zypper in -t patch slessp2-wireshark-7240

SUSE Linux Enterprise Server 11 SP2 :

zypper in -t patch slessp2-wireshark-7240

SUSE Linux Enterprise Desktop 11 SP2 :

zypper in -t patch sledsp2-wireshark-7240

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", reference:"wireshark-1.8.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"wireshark-1.8.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"wireshark-1.8.4-0.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
