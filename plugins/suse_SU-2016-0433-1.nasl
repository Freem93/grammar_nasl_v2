#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0433-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88710);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-5041", "CVE-2015-7575", "CVE-2015-7981", "CVE-2015-8126", "CVE-2015-8472", "CVE-2015-8540", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_osvdb_id(129444, 130175, 131598, 132305, 133156, 133157, 133159, 133160, 133161, 133686);

  script_name(english:"SUSE SLES11 Security Update : java-1_7_0-ibm (SUSE-SU-2016:0433-1) (SLOTH)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-ibm fixes the following issues by updating
to 7.0-9.30 (bsc#963937) :

  - CVE-2015-5041: Could could have invoked non-public
    interface methods under certain circumstances

  - CVE-2015-7575: The TLS protocol could allow weaker than
    expected security caused by a collision attack when
    using the MD5 hash function for signing a
    ServerKeyExchange message during a TLS handshake. An
    attacker could exploit this vulnerability using
    man-in-the-middle techniques to impersonate a TLS server
    and obtain credentials

  - CVE-2015-7981: libpng could allow a remote attacker to
    obtain sensitive information, caused by an out-of-bounds
    read in the png_convert_to_rfc1123 function. An attacker
    could exploit this vulnerability to obtain sensitive
    information

  - CVE-2015-8126: buffer overflow in libpng caused by
    improper bounds checking by the png_set_PLTE() and
    png_get_PLTE() functions

  - CVE-2015-8472: buffer overflow in libpng caused by
    improper bounds checking by the png_set_PLTE() and
    png_get_PLTE() functions

  - CVE-2015-8540: libpng is vulnerable to a buffer
    overflow, caused by a read underflow in
    png_check_keyword in pngwutil.c. By sending an overly
    long argument, a remote attacker could overflow a buffer
    and execute arbitrary code on the system or cause the
    application to crash.

  - CVE-2016-0402: An unspecified vulnerability related to
    the Networking component has no confidentiality impact,
    partial integrity impact, and no availability impact

  - CVE-2016-0448: An unspecified vulnerability related to
    the JMX component could allow a remote attacker to
    obtain sensitive information

  - CVE-2016-0466: An unspecified vulnerability related to
    the JAXP component could allow a remote attacker to
    cause a denial of service

  - CVE-2016-0483: An unspecified vulnerability related to
    the AWT component has complete confidentiality impact,
    complete integrity impact, and complete availability
    impact

  - CVE-2016-0494: An unspecified vulnerability related to
    the 2D component has complete confidentiality impact,
    complete integrity impact, and complete availability
    impact

The following bugs were fixed :

  - bsc#960402: resolve package conflicts in devel package

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8126.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0448.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0494.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160433-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fac1ed5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-java-1_7_0-ibm-12398=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.30-45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.30-45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-1.7.0_sr9.30-45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-devel-1.7.0_sr9.30-45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-jdbc-1.7.0_sr9.30-45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr9.30-45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr9.30-45.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-ibm");
}
