#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1851-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86703);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2014-8111", "CVE-2015-3183", "CVE-2015-3185", "CVE-2015-4000");
  script_bugtraq_id(74265, 74733, 75963, 75965);
  script_osvdb_id(120601, 122331, 123122, 123123);

  script_name(english:"SUSE SLES12 Security Update : apache2 (SUSE-SU-2015:1851-1) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Apache2 webserver was updated to fix several issues :

Security issues fixed :

  - The chunked transfer coding implementation in the Apache
    HTTP Server did not properly parse chunk headers, which
    allowed remote attackers to conduct HTTP request
    smuggling attacks via a crafted request, related to
    mishandling of large chunk-size values and invalid
    chunk-extension characters in
    modules/http/http_filters.c. [bsc#938728, CVE-2015-3183]

  - The LOGJAM security issue was addressed by: [bnc#931723
    CVE-2015-4000]

  - changing the SSLCipherSuite cipherstring to disable
    export cipher suites and deploy Ephemeral Elliptic-Curve
    Diffie-Hellman (ECDHE) ciphers.

  - Adjust 'gensslcert' script to generate a strong and
    unique Diffie Hellman Group and append it to the server
    certificate file.

  - The ap_some_auth_required function in server/request.c
    in the Apache HTTP Server 2.4.x did not consider that a
    Require directive may be associated with an
    authorization setting rather than an authentication
    setting, which allowed remote attackers to bypass
    intended access restrictions in opportunistic
    circumstances by leveraging the presence of a module
    that relies on the 2.2 API behavior. [bnc#938723
    bnc#939516 CVE-2015-3185]

  - Tomcat mod_jk information leak due to incorrect
    JkMount/JkUnmount directives processing [bnc#927845
    CVE-2014-8111]

Other bugs fixed :

  - Now provides a suse_maintenance_mmn_# [bnc#915666].

  - Hard-coded modules in the %files [bnc#444878].

  - Fixed the IfModule directive around SSLSessionCache
    [bnc#911159].

  - allow only TCP ports in Yast2 firewall files
    [bnc#931002]

  - fixed a regression when some LDAP searches or
    comparisons might be done with the wrong credentials
    when a backend connection is reused [bnc#930228]

  - Fixed split-logfile2 script [bnc#869790]

  - remove the changed MODULE_MAGIC_NUMBER_MINOR from which
    confuses modules the way that they expect functionality
    that our apache does not provide [bnc#915666]

  - gensslcert: CN now defaults to `hostname -f`
    [bnc#949766], fix help [bnc#949771]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/444878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/869790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8111.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4000.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151851-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2958bff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-772=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-772=1

SUSE Enterprise Storage 1.0 :

zypper in -t patch SUSE-Storage-1.0-2015-772=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_auth_kerb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_auth_kerb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_auth_kerb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_jk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_jk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_jk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_security2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_security2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_security2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/03");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-debuginfo-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-debugsource-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-example-pages-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_auth_kerb-5.4-2.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_auth_kerb-debuginfo-5.4-2.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_auth_kerb-debugsource-5.4-2.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_jk-1.2.40-2.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_jk-debuginfo-1.2.40-2.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_jk-debugsource-1.2.40-2.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_security2-2.8.0-3.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_security2-debuginfo-2.8.0-3.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_security2-debugsource-2.8.0-3.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-prefork-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-prefork-debuginfo-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-utils-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-utils-debuginfo-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-worker-2.4.10-14.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-worker-debuginfo-2.4.10-14.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2");
}
