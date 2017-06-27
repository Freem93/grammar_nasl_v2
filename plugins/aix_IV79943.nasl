#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory4.asc.
#

include("compat.inc");

if (description)
{
  script_id(88056);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/01/19 19:35:23 $");

  script_cve_id(
    "CVE-2015-5219",
    "CVE-2015-7691",
    "CVE-2015-7692",
    "CVE-2015-7701",
    "CVE-2015-7702",
    "CVE-2015-7850",
    "CVE-2015-7853",
    "CVE-2015-7855"
  );
  script_bugtraq_id(
    76473,
    77273,
    77274,
    77279,
    77281,
    77283,
    77285,
    77286
  );
  script_osvdb_id(
    116071,
    126665,
    129299,
    129301,
    129304,
    129307,
    129311
  );
  script_xref(name:"TRA", value:"TRA-2015-04");
  script_xref(name:"EDB-ID", value:"40840");

  script_name(english:"AIX 7.1 TL 3 : ntp (IV79943)");
  script_summary(english:"Check for APAR IV79943.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of Network Time Protocol (NTP)
installed that is affected by the following vulnerabilities :

  - A divide-by-zero error exists in file include/ntp.h
    when handling LOGTOD and ULOGTOD macros in a crafted
    NTP packet. An unauthenticated, remote attacker can
    exploit this, via crafted NTP packets, to crash ntpd.
    (CVE 2015-5219)

  - A flaw exists in the ntp_crypto.c file due to improper
    validation of the 'vallen' value in extension fields. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted autokey packets, to disclose
    sensitive information or cause a denial of service.
    (CVE-2015-7691)

  - A denial of service vulnerability exists in the autokey
    functionality due to a failure in the crypto_bob2(),
    crypto_bob3(), and cert_sign() functions to properly
    validate the 'vallen' value. An unauthenticated, remote
    attacker can exploit this, via specially crafted autokey
    packets, to crash the NTP service. (CVE-2015-7692)

  - A denial of service vulnerability exists in the
    crypto_recv() function in the file ntp_crypto.c related
    to autokey functionality. An unauthenticated, remote
    attacker can exploit this, via an ongoing flood of NTPv4
    autokey requests, to exhaust memory resources.
    (CVE-2015-7701)

  - A denial of service vulnerability exists due to improper
    validation of packets containing certain autokey
    operations. An unauthenticated, remote attacker can
    exploit this, via specially crafted autokey packets,
    to crash the NTP service. (CVE-2015-7702)

  - A denial of service vulnerability exists due to a logic
    flaw in the authreadkeys() function in the file
    authreadkeys.c when handling extended logging where the
    log and key files are set to be the same file. An
    authenticated, remote attacker can exploit this, via a
    crafted set of remote configuration requests, to cause
    the NTP service to stop responding. (CVE-2015-7850)

  - A overflow condition exists in the
    read_refclock_packet() function in the file ntp_io.c
    when handling negative data lengths. A local attacker
    can exploit this to crash the NTP service or possibly
    gain elevated privileges. (CVE-2015-7853)

  - A denial of service vulnerability exists due to an
    assertion flaw in the decodenetnum() function in the
    file decodenetnum.c when handling long data values in
    mode 6 and 7 packets. An unauthenticated, remote
    attacker can exploit this to crash the NTP service.
    (CVE-2015-7855)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory4.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2015-04");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate interim fix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 7.1", oslevel);
}

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];
if ( ml != "03" || sp != "05" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 7.1 ML 03 SP 05", oslevel + " ML " + ml + " SP " + sp);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit( 0, "This AIX package check is disabled because : " + get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_7135 = "(IV79943s5b|IV83993m5a)";

if (aix_check_ifix(release:"7.1", ml:"03", sp:"05", patch:ifixes_7135, package:"bos.net.tcp.client", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.45") < 0) flag++;

report_note = '\n' +
  'Note that iFix IV79943s5b is a mutually exclusive installation with' + '\n' +
  'iFix IV74261s5a. Neither are cumulative with each other, and both are' + '\n' +
  'required to resolve two different vulnerabilities at this package' + '\n' +
  'level. Apply cumulative iFix IV83993m5a to address both. Please contact' + '\n' +
  'IBM for further details.' + '\n';

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  aix_report_extra += report_note;
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client");
}
