#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ssh_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(73565);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/25 14:28:28 $");

  script_cve_id("CVE-2008-1483", "CVE-2008-1657");
  script_bugtraq_id(28444, 28531);
  script_osvdb_id(43745, 43911);

  script_name(english:"AIX OpenSSH Advisory : ssh_advisory.asc");
  script_summary(english:"Checks the version of the openssh client and server packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSH.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH running on the remote host is affected by the
following vulnerabilities :

  - OpenSSH 4.3p2, and probably other versions, allows local
    users to hijack forwarded X connections by causing ssh
    to set DISPLAY to :10, even when another process is
    listening on the associated port, as demonstrated by
    opening TCP port 6010 (IPv4) and sniffing a cookie sent
    by Emacs. (CVE-2008-1483)

  - OpenSSH before 4.9 allows remote authenticated users to
    bypass the sshd_config ForceCommand directive by
    modifying the .ssh/rc session file. (CVE-2008-1657)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ssh_advisory.asc");
  script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/projects/openssh-aix/files/");
  script_set_attribute(attribute:"solution",  value:
"A fix is available and can be downloaded from the OpenSSH sourceforge
website for the AIX release.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

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
if ( oslevel != "AIX-5.2" && oslevel != "AIX-5.3" && oslevel != "AIX-6.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.2 / 5.3 / 6.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if (aix_check_package(release:"5.2", package:"openssh.base.client", minpackagever:"0.0.0.0", maxpackagever:"4.7.0.5200", fixpackagever:"4.7.0.5201") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssh.base.client", minpackagever:"0.0.0.0", maxpackagever:"4.7.0.5200", fixpackagever:"4.7.0.5201") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.client", minpackagever:"0.0.0.0", maxpackagever:"4.7.0.5200", fixpackagever:"4.7.0.5201") > 0) flag++;
if (aix_check_package(release:"5.2", package:"openssh.base.server", minpackagever:"0.0.0.0", maxpackagever:"4.7.0.5200", fixpackagever:"4.7.0.5201") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssh.base.server", minpackagever:"0.0.0.0", maxpackagever:"4.7.0.5200", fixpackagever:"4.7.0.5201") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.server", minpackagever:"0.0.0.0", maxpackagever:"4.7.0.5200", fixpackagever:"4.7.0.5201") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh.base.client / openssh.base.server");
}
