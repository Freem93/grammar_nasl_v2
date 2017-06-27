#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99183);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id(
    "CVE-2015-7974",
    "CVE-2016-1547",
    "CVE-2016-1550",
    "CVE-2016-1551",
    "CVE-2016-2517",
    "CVE-2016-2518",
    "CVE-2016-2519",
    "CVE-2016-4953",
    "CVE-2016-4954",
    "CVE-2016-4955",
    "CVE-2016-4957"
  );
  script_bugtraq_id(
    81960,
    88189,
    88204,
    88219,
    88226,
    88261,
    88276,
    91007,
    91010
  );
  script_osvdb_id(
    133387,
    137711,
    137714,
    137731,
    137733,
    137734,
    137735,
    139281,
    139282,
    139283,
    139284
  );
  script_xref(name:"CERT", value:"321640");
  script_xref(name:"CERT", value:"718152");

  script_name(english:"AIX NTP v4 Advisory : ntp_advisory7.asc (IV87278) (IV87279)");
  script_summary(english:"Checks the version of the ntp packages for appropriate iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NTP installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NTP installed on the remote AIX host is affected by
the following vulnerabilities :

  - A time serving flaw exists in the trusted key system
    due to improper key checks. An authenticated, remote
    attacker can exploit this to perform impersonation
    attacks between authenticated peers. (CVE-2015-7974)

  - A denial of service vulnerability exists due to improper
    handling of a crafted Crypto NAK Packet with a source
    address spoofed to match that of an existing associated
    peer. An unauthenticated, remote attacker can exploit
    this to demobilize a client association. (CVE-2016-1547)

  - An information disclosure vulnerability exists in the
    message authentication functionality in libntp that is
    triggered during the handling of a series of specially
    crafted messages. An adjacent attacker can exploit this
    to partially recover the message digest key.
    (CVE-2016-1550)

  - A flaw exists due to improper filtering of IPv4 'bogon'
    packets received from a network. An unauthenticated,
    remote attacker can exploit this to spoof packets to
    appear to come from a specific reference clock.
    (CVE-2016-1551)

  - A denial of service vulnerability exists that allows an
    authenticated, remote attacker to manipulate the value
    of the trustedkey, controlkey, or requestkey via a
    crafted packet, preventing authentication with ntpd
    until the daemon has been restarted. (CVE-2016-2517)

  - An out-of-bounds read error exists in the MATCH_ASSOC()
    function that occurs during the creation of peer
    associations with hmode greater than 7. An
    authenticated, remote attacker can exploit this, via a
    specially crafted packet, to cause a denial of service.
    (CVE-2016-2518)

  - An overflow condition exists in the ctl_getitem()
    function in ntpd due to improper validation of
    user-supplied input when reporting return values. An
    authenticated, remote attacker can exploit this to cause
    ntpd to abort. (CVE-2016-2519)

  - A denial of service vulnerability exists when handling
    authentication due to improper packet timestamp checks.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted and spoofed packet, to
    demobilize the ephemeral associations. (CVE-2016-4953)

  - A flaw exists that is triggered when handling spoofed
    packets. An unauthenticated, remote attacker can exploit
    this, via specially crafted packets, to affect peer
    variables (e.g., cause leap indications to be set). Note
    that the attacker must be able to spoof packets with
    correct origin timestamps from servers before expected
    response packets arrive. (CVE-2016-4954)

  - A flaw exists that is triggered when handling spoofed
    packets. An unauthenticated, remote attacker can exploit
    this, via specially crafted packets, to reset autokey
    associations. Note that the attacker must be able to
    spoof packets with correct origin timestamps from
    servers before expected response packets arrive.
    (CVE-2016-4955)

  - A denial of service vulnerability exists when handling
    CRYPTO_NAK packets that allows an unauthenticated,
    remote attacker to cause a crash. Note that this issue
    only affects versions 4.2.8p7 and 4.3.92.
    (CVE-2016-4957)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory7.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
if ( oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_6 = "(IV87278s7a|IV92287m5a)";
ifixes_7 = "(IV87279s7a|IV92126m3a)";

if (aix_check_ifix(release:"6.1", patch:ifixes_6, package:"ntp.rte", minfilesetver:"6.1.6.0", maxfilesetver:"6.1.6.7") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_7, package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.7") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_7, package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.7") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp.rte");
}
