#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory2.asc.
#

include("compat.inc");

if (description)
{
  script_id(81275);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/19 19:35:23 $");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9294",
    "CVE-2014-9295"
  );
  script_bugtraq_id(
    71757,
    71761,
    71762
  );
  script_osvdb_id(
    116066,
    116067,
    116068,
    116069,
    116074
  );
  script_xref(name:"CERT", value:"852879");

  script_name(english:"AIX 7.1 TL 3 : ntp (IV68430)");
  script_summary(english:"Check for APAR IV68430.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of NTP installed on the remote AIX host is affected by
the following vulnerabilities :

  - A security weakness exists due to the config_auth()
    function improperly generating default keys when no
    authentication key is defined in the ntp.conf file.
    Key size is limited to 31 bits and the insecure
    ntp_random() function is used, resulting in
    cryptographically-weak keys with insufficient entropy. A
    remote attacker can exploit this to defeat cryptographic
    protection mechanisms via a brute-force attack.
    (CVE-2014-9293)

  - A security weakness exists due the use of a weak seed to
    prepare a random number generator used to generate
    symmetric keys. This allows a remote attacker to defeat
    cryptographic protection mechanisms via a brute-force
    attack. (CVE-2014-9294)

  - Multiple stack-based buffer overflow conditions exist
    due to improper validation of user-supplied input when
    handling packets in the crypto_recv(), ctl_putdata(),
    and configure() functions when using autokey
    authentication. A remote attacker can exploit this, via
    a specially crafted packet, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2014-9295)");
  script_set_attribute(attribute:"see_also",value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory2.asc");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate interim fix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
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
if ( ml != "03" || sp != "04" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 7.1 ML 03 SP 04", oslevel + " ML " + ml + " SP " + sp);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_71330 = "(IV68430s4a|IV83993m4b)";

if (aix_check_ifix(release:"7.1", ml:"03", sp:"04", patch:ifixes_71330, package:"bos.net.tcp.client", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.30") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
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

