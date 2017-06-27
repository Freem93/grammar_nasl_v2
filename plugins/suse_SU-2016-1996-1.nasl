#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1996-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93271);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2011-3205", "CVE-2011-4096", "CVE-2012-5643", "CVE-2013-0188", "CVE-2013-4115", "CVE-2014-0128", "CVE-2014-6270", "CVE-2014-7141", "CVE-2014-7142", "CVE-2015-5400", "CVE-2016-2390", "CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-2572", "CVE-2016-3947", "CVE-2016-3948", "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_bugtraq_id(49356, 50449, 56957, 61111, 66112, 69686, 69688, 70022);
  script_osvdb_id(74847, 76742, 88492, 95165, 104375, 111286, 111420, 112409, 124237, 134626, 134900, 134901, 136595, 136596, 137402, 137403, 137404, 137405, 138132, 138133, 138134);

  script_name(english:"SUSE SLES11 Security Update : squid3 (SUSE-SU-2016:1996-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for squid3 fixes the following issues :

  - Multiple issues in pinger ICMP processing.
    (CVE-2014-7141, CVE-2014-7142)

  - CVE-2016-3947: Buffer overrun issue in pinger ICMPv6
    processing. (bsc#973782)

  - CVE-2016-4554: fix header smuggling issue in HTTP
    Request processing (bsc#979010)

  - fix multiple Denial of Service issues in HTTP Response
    processing. (CVE-2016-2569, CVE-2016-2570,
    CVE-2016-2571, CVE-2016-2572, bsc#968392, bsc#968393,
    bsc#968394, bsc#968395)

  - CVE-2016-3948: Fix denial of service in HTTP Response
    processing (bsc#973783)

  - CVE-2016-4051: fixes buffer overflow in cachemgr.cgi
    (bsc#976553)

  - CVE-2016-4052, CVE-2016-4053, CVE-2016-4054 :

  - fixes multiple issues in ESI processing (bsc#976556)

  - CVE-2016-4556: fixes double free vulnerability in Esi.cc
    (bsc#979008)

  - CVE-2015-5400: Improper Protection of Alternate Path
    (bsc#938715)

  - CVE-2014-6270: fix off-by-one in snmp subsystem
    (bsc#895773)

  - Memory leak in squid3 when using external_acl
    (bsc#976708)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/895773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-3205.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2011-4096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-5643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-0188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0128.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-6270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5400.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2390.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3947.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3948.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4556.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161996-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b61fb15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-squid3-12682=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-squid3-12682=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"squid3-3.1.23-8.16.27.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid3");
}
