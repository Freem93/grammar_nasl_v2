#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssh_advisory4.asc.
#

include("compat.inc");

if (description)
{
  script_id(85930);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/01 17:47:58 $");

  script_cve_id("CVE-2015-5352");
  script_bugtraq_id(75525);
  script_osvdb_id(124008);

  script_name(english:"AIX OpenSSH Vulnerability : openssh_advisory5.asc");
  script_summary(english:"Checks the version of the openssh client and server packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a vulnerable version of OpenSSH.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH running on the remote host is affected by a
security bypass vulnerability due to a failure to check the refusal
deadline during the forwarding of untrusted X11 connections. A remote
attacker can exploit this to bypass timeout checks and XSECURITY
restrictions.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssh_advisory5.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat OpenSSH_6.0.0.6110.tar.Z | tar xvf -
  (or)
  zcat OpenSSH_6.0.0.6201.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that an mksysb backup of
the system be created. Verify it is both bootable and readable before
proceeding.

To preview the fix installation :

  installp -apYd . OpenSSH_6.0.0.6110
  (or)
  installp -apYd . OpenSSH_6.0.0.6201

To install the fix package:

  installp -aXYd . OpenSSH_6.0.0.6110
  (or)            
  installp -aXYd . OpenSSH_6.0.0.6201");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/14");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if (aix_check_package(release:"5.3", package:"openssh.base.client", minpackagever:"4.0.0.5200", maxpackagever:"6.0.0.6109", fixpackagever:"6.0.0.6110") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssh.base.client", minpackagever:"6.0.0.6200", maxpackagever:"6.0.0.6200", fixpackagever:"6.0.0.6201") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.client", minpackagever:"4.0.0.5200", maxpackagever:"6.0.0.6109", fixpackagever:"6.0.0.6110") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.client", minpackagever:"6.0.0.6200", maxpackagever:"6.0.0.6200", fixpackagever:"6.0.0.6201") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssh.base.client", minpackagever:"4.0.0.5200", maxpackagever:"6.0.0.6109", fixpackagever:"6.0.0.6110") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssh.base.client", minpackagever:"6.0.0.6200", maxpackagever:"6.0.0.6200", fixpackagever:"6.0.0.6201") > 0) flag++;

if (aix_check_package(release:"5.3", package:"openssh.base.server", minpackagever:"4.0.0.5200", maxpackagever:"6.0.0.6109", fixpackagever:"6.0.0.6110") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssh.base.server", minpackagever:"6.0.0.6200", maxpackagever:"6.0.0.6200", fixpackagever:"6.0.0.6201") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.server", minpackagever:"4.0.0.5200", maxpackagever:"6.0.0.6109", fixpackagever:"6.0.0.6110") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.server", minpackagever:"6.0.0.6200", maxpackagever:"6.0.0.6200", fixpackagever:"6.0.0.6201") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssh.base.server", minpackagever:"4.0.0.5200", maxpackagever:"6.0.0.6109", fixpackagever:"6.0.0.6110") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssh.base.server", minpackagever:"6.0.0.6200", maxpackagever:"6.0.0.6200", fixpackagever:"6.0.0.6201") > 0) flag++;

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
