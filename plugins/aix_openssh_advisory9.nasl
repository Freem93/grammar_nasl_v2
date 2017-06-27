#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95477);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/05 14:31:49 $");

  script_cve_id(
    "CVE-2015-8325",
    "CVE-2016-6210",
    "CVE-2016-6515"
  );
  script_bugtraq_id(
    86187,
    91812,
    92212
  );
  script_osvdb_id(
    137226,
    141586,
    142342
  );
  script_xref(name:"EDB-ID", value:"40113");
  script_xref(name:"EDB-ID", value:"40136");

  script_name(english:"AIX OpenSSH Advisory : openssh_advisory9.asc");
  script_summary(english:"Checks the version of the OpenSSH packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of OpenSSH installed that is
affected by the following vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    do_setup_env() function within file session.c when
    handling user-supplied environmental variables. A local
    attacker can exploit this to gain elevated privileges by
    triggering a crafted environment for the /bin/login
    program. This vulnerability requires that the UseLogin
    feature is enabled and that PAM is configured to read
    .pam_environment files in user home directories.
    (CVE-2015-8325)

  - A flaw exists when handling authentication requests that
    involve overly long passwords due to returning shorter
    response times for requests for invalid users than for
    valid users. An unauthenticated, remote attacker can
    exploit this to enumerate valid usernames by conducting
    a timing attack. (CVE-2016-6210)

  - A denial of service vulnerability exists in the
    auth_password() function within auth-passwd.c due to a
    a failure to limit password lengths. An unauthenticated,
    remote attacker can exploit this, via overly long
    passwords, to cause the excessive consumption of CPU
    resources. (CVE-2016-6515)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssh_advisory9.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
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
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_6202 = "(6202_ifix)";


if (aix_check_ifix(release:"5.3", patch:ifixes_6202, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6202, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6202, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_6202, package:"openssh.base.client", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;

if (aix_check_ifix(release:"5.3", patch:ifixes_6202, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;
if (aix_check_ifix(release:"6.1", patch:ifixes_6202, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;
if (aix_check_ifix(release:"7.1", patch:ifixes_6202, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;
if (aix_check_ifix(release:"7.2", patch:ifixes_6202, package:"openssh.base.server", minfilesetver:"4.0.0.5200", maxfilesetver:"6.0.0.6202") < 0) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh.base.client / openssh.base.server");
}
