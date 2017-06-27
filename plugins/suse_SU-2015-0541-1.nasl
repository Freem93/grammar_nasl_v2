#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0541-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83703);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0293");
  script_bugtraq_id(73196, 73225, 73227, 73231, 73232, 73237, 73239);
  script_osvdb_id(118817, 119328, 119755, 119756, 119757, 119761);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssl (SUSE-SU-2015:0541-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL was updated to fix various security issues.

Following security issues were fixed :

  - CVE-2015-0209: A Use After Free following
    d2i_ECPrivatekey error was fixed which could lead to
    crashes for attacker supplied Elliptic Curve keys. This
    could be exploited over SSL connections with client
    supplied keys.

  - CVE-2015-0286: A segmentation fault in ASN1_TYPE_cmp was
    fixed that could be exploited by attackers when e.g.
    client authentication is used. This could be exploited
    over SSL connections.

  - CVE-2015-0287: A ASN.1 structure reuse memory corruption
    was fixed. This problem can not be exploited over
    regular SSL connections, only if specific client
    programs use specific ASN.1 routines.

  - CVE-2015-0288: A X509_to_X509_REQ NULL pointer
    dereference was fixed, which could lead to crashes. This
    function is not commonly used, and not reachable over
    SSL methods.

  - CVE-2015-0289: Several PKCS7 NULL pointer dereferences
    were fixed, which could lead to crashes of programs
    using the PKCS7 APIs. The SSL apis do not use those by
    default.

  - CVE-2015-0293: Denial of service via reachable assert in
    SSLv2 servers, could be used by remote attackers to
    terminate the server process. Note that this requires
    SSLv2 being allowed, which is not the default.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0286.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0287.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0289.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0293.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922500"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150541-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce7c4e1f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-133=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-133=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-133=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-debuginfo-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-hmac-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-debuginfo-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-debugsource-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-32bit-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1i-20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-debugsource-1.0.1i-20.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
