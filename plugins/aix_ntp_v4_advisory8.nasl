#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99184);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/17 17:37:51 $");

  script_cve_id(
    "CVE-2016-7427",
    "CVE-2016-7428",
    "CVE-2016-9310",
    "CVE-2016-9311"
  );
  script_bugtraq_id(
    94444,
    94446,
    94447,
    94452
  );
  script_osvdb_id(
    147594,
    147595,
    147596,
    147597
  );
  script_xref(name:"CERT", value:"633847");

  script_name(english:"AIX NTP v4 Advisory : ntp_advisory8.asc (IV92126) (IV92287)");
  script_summary(english:"Checks the version of the ntp packages for appropriate iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NTP installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NTP installed on the remote AIX host is affected by
the following vulnerabilities :

  - A denial of service vulnerability exists in the
    broadcast mode replay prevention functionality. An
    unauthenticated, adjacent attacker can exploit this, via
    specially crafted broadcast mode NTP packets
    periodically injected into the broadcast domain, to
    cause ntpd to reject broadcast mode packets from
    legitimate NTP broadcast servers. (CVE-2016-7427)

  - A denial of service vulnerability exists in the
    broadcast mode poll interval functionality. An
    unauthenticated, adjacent attacker can exploit this, via
    specially crafted broadcast mode NTP packets, to cause
    ntpd to reject packets from a legitimate NTP broadcast
    server. (CVE-2016-7428)

  - A flaw exists in the control mode (mode 6) functionality
    when handling specially crafted control mode packets. An
    unauthenticated, adjacent attacker can exploit this to
    set or disable ntpd traps, resulting in the disclosure
    of potentially sensitive information, disabling of
    legitimate monitoring, or DDoS amplification.
    (CVE-2016-9310)

  - A NULL pointer dereference flaw exists in the
    report_event() function within file ntpd/ntp_control.c
    when the trap service handles certain peer events. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted packet, to cause a denial of service
    condition. (CVE-2016-9311)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory8.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
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

ifixes_6 = "IV92287m5a";
ifixes_7 = "IV92126m3a";

if (aix_check_ifix(release:"6.1", patch:ifixes_6, package:"ntp.rte", minfilesetver:"6.1.6.0", maxfilesetver:"6.1.6.7") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_7, package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.7") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_7, package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.7") < 0) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp.rte");
}
