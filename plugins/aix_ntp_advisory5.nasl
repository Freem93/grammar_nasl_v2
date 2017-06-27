#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory5.asc.
#

include("compat.inc");

if (description)
{
  script_id(89672);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:06:02 $");

  script_cve_id("CVE-2015-5300");
  script_bugtraq_id(77312);
  script_osvdb_id(129315);

  script_name(english:"AIX NTP Advisory : ntp_advisory5 (IV81129) (IV81130)");
  script_summary(english:"Check for APAR IV81129 / IV81130.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"A version of the Network Time Protocol (NTP) package installed on the
remote AIX host is affected by an integrity vulnerability due to an
improperly implemented threshold limitation for the '-g' option. A
man-in-the-middle attacker can exploit this to intercept the NTP
traffic and return arbitrary date and time values to the user.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory5.asc");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate interim fix as referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (aix_check_ifix(release:"6.1", ml:"09", patch:"IV81129m6a", package:"ntp.rte", minfilesetver:"6.1.6.0", maxfilesetver:"6.1.6.4") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"03", patch:"IV81130m5a", package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.4") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", patch:"IV81130m5a", package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.4") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"00", patch:"IV81130m5a", package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.4") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
