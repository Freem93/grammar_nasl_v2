#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86656);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/14 14:28:21 $");

  script_cve_id("CVE-2015-6563", "CVE-2015-6564");
  script_bugtraq_id(76317);
  script_osvdb_id(126030, 126033);

  script_name(english:"AIX OpenSSH Advisory : openssh_advisory6.asc");
  script_summary(english:"Checks the version of the OpenSSH packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by the following vulnerabilities :

  - A flaw exists in the monitor component when handling
    extraneous username data in MONITOR_REQ_PAM_INIT_CTX
    requests. A local attacker can exploit this issue to
    conduct an impersonation attack, by sending a crafted
    MONITOR_REQ_PWNAM request that leverages any SSH login
    access with control of the sshd UID. (CVE-2015-6563)

  - A use-after-free error exists in function
    mm_answer_pam_free_ctx() in the file monitor.c when
    handling MONITOR_REQ_PAM_FREE_CTX requests. A local
    attacker can exploit this to gain elevated privileges,
    by leveraging control of the sshd UID to send an
    unexpectedly early MONITOR_REQ_PAM_FREE_CTX request.
    (CVE-2015-6564)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssh_advisory6.asc");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/marketing/iwm/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_6110 = "(6110_ifix|IV80743m9b|IV84698m9b)";
ifixes_6201 = "(6201_ifix|IV80743m9a|IV84698m9a)";

if (aix_check_ifix(release:"5.3", patch:ifixes_6110, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6110") < 0) flag++;
if (aix_check_ifix(release:"5.3", patch:ifixes_6201, package:"openssh.base.client", minfilesetver:"6.0.0.6200", maxfilesetver:"6.0.0.6201") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6110, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6110") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6201, package:"openssh.base.client", minfilesetver:"6.0.0.6200", maxfilesetver:"6.0.0.6201") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6110, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6110") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6201, package:"openssh.base.client", minfilesetver:"6.0.0.6200", maxfilesetver:"6.0.0.6201") < 0) flag++;

if (aix_check_ifix(release:"5.3", patch:ifixes_6110, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6110") < 0) flag++;
if (aix_check_ifix(release:"5.3", patch:ifixes_6201, package:"openssh.base.server", minfilesetver:"6.0.0.6200", maxfilesetver:"6.0.0.6201") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6110, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6110") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6201, package:"openssh.base.server", minfilesetver:"6.0.0.6200", maxfilesetver:"6.0.0.6201") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6110, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6110") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6201, package:"openssh.base.server", minfilesetver:"6.0.0.6200", maxfilesetver:"6.0.0.6201") < 0) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh.base.client / openssh.base.server");
}
