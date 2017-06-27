#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory rsyslog_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(79660);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id("CVE-2014-3634", "CVE-2014-3683");
  script_bugtraq_id(70187, 70243);
  script_osvdb_id(112338, 112596);

  script_name(english:"AIX rsyslog Advisory : rsyslog_advisory.asc");
  script_summary(english:"Checks the version of the rsyslog package.");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host has a vulnerable version of rsyslog.");
  script_set_attribute(attribute:"description", value:
"The version of rsyslog installed on the remote AIX host is affected by
a remote code execution or denial of service vulnerability :

  - The installed rsyslog allows remote attackers to cause a
    denial of service (crash), possibly execute arbitrary
    code, or have other unspecified impacts by crafting a
    priority (PRI) value that triggers an out-of-bounds
    array access. (CVE-2014-3634)

  - The original fix for the above issue still retained a
    denial of service vulnerability when large PRI values
    were encountered. (CVE-2014-3683)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/rsyslog_advisory.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

To extract the fixes from the tar file :

 tar xvf rsyslog_fix.tar

IMPORTANT : it is recommended that a mksysb backup of the system be
created if possible. Verify that it is both bootable and readable
before proceeding.

To preview the fix installation :

 installp -a -d rsyslog.base -p all

To install the fix package :

 installp -a -d rsyslog.base -X all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsyslog:rsyslog");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

# 5.8.6.1 and 5.8.6.2 have no iFix; fix is 5.8.6.4.
if (aix_check_package(release:"5.3", package:"rsyslog.base", minpackagever:"5.8.6.1", maxpackagever:"5.8.6.2", fixpackagever:"5.8.6.4") > 0) flag++;
if (aix_check_package(release:"6.1", package:"rsyslog.base", minpackagever:"5.8.6.1", maxpackagever:"5.8.6.2", fixpackagever:"5.8.6.4") > 0) flag++;
if (aix_check_package(release:"7.1", package:"rsyslog.base", minpackagever:"5.8.6.1", maxpackagever:"5.8.6.2", fixpackagever:"5.8.6.4") > 0) flag++;

# 5.8.6.3 has an iFix
if (aix_check_ifix(release:"5.3", patch:"IV66633s0a", package:"rsyslog.base", minfilesetver:"5.8.6.3", maxfilesetver:"5.8.6.3") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:"IV66633s0a", package:"rsyslog.base", minfilesetver:"5.8.6.3", maxfilesetver:"5.8.6.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:"IV66633s0a", package:"rsyslog.base", minfilesetver:"5.8.6.3", maxfilesetver:"5.8.6.3") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
