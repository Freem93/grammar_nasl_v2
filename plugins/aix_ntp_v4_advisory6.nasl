#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92357);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2015-7973",
    "CVE-2015-7977",
    "CVE-2015-7979",
    "CVE-2015-8139",
    "CVE-2015-8140",
    "CVE-2015-8158"
  );
  script_bugtraq_id(
    81814,
    81815,
    81816,
    81963,
    82102,
    82105
  );
  script_osvdb_id(
    133378,
    133382,
    133388,
    133389,
    133390,
    133391,
    133414
  );
  script_xref(name:"CERT", value:"718152");

  script_name(english:"AIX NTP v4 Advisory : ntp_advisory6.asc (IV83983) (IV83992)");
  script_summary(english:"Checks the version of the ntp packages for appropriate iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NTP installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NTP installed on the remote AIX host is affected by
the following vulnerabilities :

  - A flaw exists in the receive() function due to the use
    of authenticated broadcast mode. A man-in-the-middle
    attacker can exploit this to conduct a replay attack.
    (CVE-2015-7973)

  - A NULL pointer dereference flaw exists in ntp_request.c
    that is triggered when handling ntpdc relist commands.
    A remote attacker can exploit this, via a specially
    crafted request, to crash the service, resulting in a
    denial of service condition. (CVE-2015-7977)

  - An unspecified flaw exists in authenticated broadcast
    mode. A remote attacker can exploit this, via specially
    crafted packets, to cause a denial of service condition.
    (CVE-2015-7979)

  - A flaw exists in ntpq and ntpdc that allows a remote
    attacker to disclose sensitive information in
    timestamps. (CVE-2015-8139)

  - A flaw exists in the ntpq protocol that is triggered
    during the handling of an improper sequence of numbers.
    A man-in-the-middle attacker can exploit this to conduct
    a replay attack. (CVE-2015-8140)

  - A flaw exists in the ntpq client that is triggered when
    handling packets that cause a loop in the getresponse()
    function. A remote attacker can exploit this to cause an
    infinite loop, resulting in a denial of service
    condition. (CVE-2015-8158)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory6.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
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

ifixes_6 = "(IV83992s5a)";
ifixes_7 = "(IV83983s5a|IV87279s7a)";

if (aix_check_ifix(release:"6.1", patch:ifixes_6, package:"ntp.rte", minfilesetver:"6.1.6.0", maxfilesetver:"6.1.6.5") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_7, package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.5") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_7, package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.5") < 0) flag++;

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
