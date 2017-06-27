#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2251-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87338);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-3195");
  script_osvdb_id(131039);

  script_name(english:"SUSE SLED11 Security Update : compat-openssl097g (SUSE-SU-2015:2251-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for compat-openssl097g fixes the following issues :

Security issue fixed :

  - CVE-2015-3195: When presented with a malformed
    X509_ATTRIBUTE structure OpenSSL would leak memory. This
    structure is used by the PKCS#7 and CMS routines so any
    application which reads PKCS#7 or CMS data from
    untrusted sources is affected. SSL/TLS is not affected.
    (bsc#957812)

A non security issue fixed :

  - Prevent segfault in s_client with invalid options
    (bsc#952099)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3195.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152251-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c25a0b2d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 11-SP4 :

zypper in -t patch slesappsp4-compat-openssl097g-12255=1

SUSE Linux Enterprise Server for SAP 11-SP3 :

zypper in -t patch slesappsp3-compat-openssl097g-12255=1

SUSE Linux Enterprise Server for SAP 11-SP2 :

zypper in -t patch slesapp2-compat-openssl097g-12255=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-compat-openssl097g-12255=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-compat-openssl097g-12255=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-compat-openssl097g-12255=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-compat-openssl097g-12255=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-compat-openssl097g-12255=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:compat-openssl097g");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/14");
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
if (! ereg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"compat-openssl097g-0.9.7g-146.22.36.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"compat-openssl097g-32bit-0.9.7g-146.22.36.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"compat-openssl097g-0.9.7g-146.22.36.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"compat-openssl097g-0.9.7g-146.22.36.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"compat-openssl097g-32bit-0.9.7g-146.22.36.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"compat-openssl097g-0.9.7g-146.22.36.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openssl097g");
}
