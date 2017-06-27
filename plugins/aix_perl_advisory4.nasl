#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory perl_advisory4.asc.
#

include("compat.inc");

if (description)
{
  script_id(73735);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2012-6329");
  script_bugtraq_id(56852);
  script_osvdb_id(88272);

  script_name(english:"AIX Perl Advisory : perl_advisory4.asc");
  script_summary(english:"Checks the version of the perl package");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host has a vulnerable version of Perl.");
  script_set_attribute(attribute:"description", value:
"The version of Perl on the remote host is affected by a code execution
vulnerability. 

The _compile function in Locale::Maketext in Perl before 5.17.7 does
not properly handle backslashes and fully qualified method names
during compilation of bracket notation. This could allow context-
dependent attackers to execute arbitrary commands via crafted input.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/perl_advisory4.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.
For AIX 5.3 or AIX 6.1, use perl61.zip, and for AIX 7.1 use
perl71.zip.

IMPORTANT : If possible, it is recommended that a mksysb backup of the
system be created.  Verify it is both bootable and readable before
proceeding. 

To preview the fix installation :

  installp -apYd . perl

To install the fix package :

  installp -aXYd . perl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki 5.1.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:perl:perl");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/28");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (aix_check_package(release:"5.3", ml:"12", package:"perl.rte", minpackagever:"5.8.8.0", maxpackagever:"5.8.8.123", fixpackagever:"5.8.8.124") > 0) flag++;
if (aix_check_package(release:"6.1", ml:"07", package:"perl.rte", minpackagever:"5.8.8.0", maxpackagever:"5.8.8.122", fixpackagever:"5.8.8.123") > 0) flag++;
if (aix_check_package(release:"6.1", ml:"08", package:"perl.rte", minpackagever:"5.8.8.0", maxpackagever:"5.8.8.244", fixpackagever:"5.8.8.245") > 0) flag++;
if (aix_check_package(release:"6.1", ml:"09", package:"perl.rte", minpackagever:"5.8.8.0", maxpackagever:"5.8.8.366", fixpackagever:"5.8.8.367") > 0) flag++;
if (aix_check_package(release:"7.1", ml:"01", package:"perl.rte", minpackagever:"5.10.1.0", maxpackagever:"5.10.1.100", fixpackagever:"5.10.1.101") > 0) flag++;
if (aix_check_package(release:"7.1", ml:"02", package:"perl.rte", minpackagever:"5.10.1.0", maxpackagever:"5.10.1.150", fixpackagever:"5.10.1.151") > 0) flag++;
if (aix_check_package(release:"7.1", ml:"03", package:"perl.rte", minpackagever:"5.10.1.0", maxpackagever:"5.10.1.200", fixpackagever:"5.10.1.201") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl.rte");
}
