#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2285-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93457);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2013-4566", "CVE-2014-3566", "CVE-2015-5244", "CVE-2016-3099");
  script_bugtraq_id(64114, 70574);
  script_osvdb_id(100516, 113251, 127774, 137597);

  script_name(english:"SUSE SLES12 Security Update : apache2-mod_nss (SUSE-SU-2016:2285-1) (POODLE)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides apache2-mod_nss 1.0.14, which brings several
fixes and enhancements :

  - Fix OpenSSL ciphers stopped parsing at +.
    (CVE-2016-3099)

  - Created valgrind suppression files to ease debugging.

  - Implement SSL_PPTYPE_FILTER to call executables to get
    the key password pins.

  - Improvements to migrate.pl.

  - Update default ciphers to something more modern and
    secure.

  - Check for host and netstat commands in gencert before
    trying to use them.

  - Add server support for DHE ciphers.

  - Extract SAN from server/client certificates into env

  - Fix memory leaks and other coding issues caught by clang
    analyzer.

  - Add support for Server Name Indication (SNI).

  - Add support for SNI for reverse proxy connections.

  - Add RenegBufferSize? option.

  - Add support for TLS Session Tickets (RFC 5077).

  - Fix logical AND support in OpenSSL cipher compatibility.

  - Correctly handle disabled ciphers. (CVE-2015-5244)

  - Implement a slew more OpenSSL cipher macros.

  - Fix a number of illegal memory accesses and memory
    leaks.

  - Support for SHA384 ciphers if they are available in NSS.

  - Add compatibility for mod_ssl-style cipher definitions.

  - Add TLSv1.2-specific ciphers.

  - Completely remove support for SSLv2.

  - Add support for sqlite NSS databases.

  - Compare subject CN and VS hostname during server start
    up.

  - Add support for enabling TLS v1.2.

  - Don't enable SSL 3 by default. (CVE-2014-3566)

  - Fix CVE-2013-4566.

  - Move nss_pcache to /usr/libexec.

  - Support httpd 2.4+.

  - Use apache2-systemd-ask-pass to prompt for a certificate
    passphrase. (bsc#972968, bsc#975394)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3099.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162285-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?840ac73d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1335=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_nss-1.0.14-18.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_nss-debuginfo-1.0.14-18.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_nss-debugsource-1.0.14-18.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_nss");
}
