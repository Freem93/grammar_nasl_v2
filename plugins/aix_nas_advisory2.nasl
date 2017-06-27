#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory nas_advisory2.asc.
#

include("compat.inc");

if (description)
{
  script_id(81022);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2014-5351");
  script_bugtraq_id(70380);
  script_osvdb_id(111907);

  script_name(english:"AIX NAS Advisory : nas_advisory2.asc");
  script_summary(english:"Checks the version of the krb5 packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of NAS installed that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Network Authentication Service (NAS) installed on
the remote AIX host is affected by a vulnerability related to
Kerberos 5 which allows authenticated users to retrieve current keys,
which can be used to forge tickets.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/nas_advisory2.asc");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=aixbp&lang=en_US&S_PKG=nas&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b39d08f");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the AIX website.

If the NAS fileset level is below 1.5.0.7, then install version
1.5.0.7.

If the NAS fileset level is at 1.6.0.0 through 1.6.0.1, then install
version 1.6.0.2. The 1.6.0.X branch is a separate release branch for
NAS SPNEGO feature.

To extract the fixes from the tar file, use the command :
  zcat NAS_1.X.0.X_aix_image.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of the
system be created. Verify that it is both bootable and readable before
proceeding.

To preview the fix installation, use the command :

 installp -a - fix_name -p all

To install the fix package, use the command :

 installp -a - fix_name -X all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(415);
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mit:kerberos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");

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

#below 1.5.0.7, 1.6.0.0-1 client
if (
  aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0 ||
  aix_check_package(release:"5.3", package:"krb5.client.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.client.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.client.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0
)
{
  flag++;
}

#below 1.5.0.7, 1.6.0.0-1 server
if (
  aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"0.0.0.0", maxpackagever:"1.5.0.6", fixpackagever:"1.5.0.7") > 0 ||
  aix_check_package(release:"5.3", package:"krb5.server.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0 ||
  aix_check_package(release:"6.1", package:"krb5.server.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0 ||
  aix_check_package(release:"7.1", package:"krb5.server.rte", minpackagever:"1.6.0.0", maxpackagever:"1.6.0.1", fixpackagever:"1.6.0.2") > 0
)
{
  flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5.client.rte / krb5.server.rte");
}
