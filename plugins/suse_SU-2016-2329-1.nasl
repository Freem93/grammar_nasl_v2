#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2329-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93590);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2013-4566", "CVE-2014-3566");
  script_bugtraq_id(64114, 70574);
  script_osvdb_id(100516, 113251);

  script_name(english:"SUSE SLES11 Security Update : apache2-mod_nss (SUSE-SU-2016:2329-1) (POODLE)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides apache2-mod_nss 1.0.14, which brings several
fixes and enhancements :

  - SHA256 cipher names change spelling from *_sha256 to
    *_sha_256.

  - Drop mod_nss_migrate.pl and use upstream migrate script
    instead.

  - Check for Apache user owner/group read permissions of
    NSS database at startup.

  - Update default ciphers to something more modern and
    secure.

  - Check for host and netstat commands in gencert before
    trying to use them.

  - Don't ignore NSSProtocol when NSSFIPS is enabled.

  - Use proper shell syntax to avoid creating /0 in gencert.

  - Add server support for DHE ciphers.

  - Extract SAN from server/client certificates into env.

  - Fix memory leaks and other coding issues caught by clang
    analyzer.

  - Add support for Server Name Indication (SNI)

  - Add support for SNI for reverse proxy connections.

  - Add RenegBufferSize? option.

  - Add support for TLS Session Tickets (RFC 5077).

  - Implement a slew more OpenSSL cipher macros.

  - Fix a number of illegal memory accesses and memory
    leaks.

  - Support for SHA384 ciphers if they are available in the
    version of NSS mod_nss is built against.

  - Add the SECURE_RENEG environment variable.

  - Add some hints when NSS database cannot be initialized.

  - Code cleanup including trailing whitespace and compiler
    warnings.

  - Modernize autotools configuration slightly, add
    config.h.

  - Add small test suite for SNI.

  - Add compatibility for mod_ssl-style cipher definitions.

  - Add Camelia ciphers.

  - Remove Fortezza ciphers.

  - Add TLSv1.2-specific ciphers.

  - Initialize cipher list when re-negotiating handshake.

  - Completely remove support for SSLv2.

  - Add support for sqlite NSS databases.

  - Compare subject CN and VS hostname during server start
    up.

  - Add support for enabling TLS v1.2.

  - Don't enable SSL 3 by default. (CVE-2014-3566)

  - Improve protocol testing.

  - Add nss_pcache man page.

  - Fix argument handling in nss_pcache.

  - Support httpd 2.4+.

  - Allow users to configure a helper to ask for certificate
    passphrases via NSSPassPhraseDialog. (bsc#975394)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162329-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8de810d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch
sleclo50sp3-apache2-mod_nss-12751=1

SUSE Manager Proxy 2.1:zypper in -t patch
slemap21-apache2-mod_nss-12751=1

SUSE Manager 2.1:zypper in -t patch sleman21-apache2-mod_nss-12751=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-apache2-mod_nss-12751=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-apache2-mod_nss-12751=1

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-apache2-mod_nss-12751=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-apache2-mod_nss-12751=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-apache2-mod_nss-12751=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-apache2-mod_nss-12751=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-apache2-mod_nss-12751=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/19");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-mod_nss-1.0.14-0.4.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-mod_nss-1.0.14-0.4.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"apache2-mod_nss-1.0.14-0.4.25.1")) flag++;


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
