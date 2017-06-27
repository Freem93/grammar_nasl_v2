#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jul2015.
#

include("compat.inc");

if (description)
{
  script_id(84807);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id("CVE-2015-4750");
  script_bugtraq_id(75862);
  script_osvdb_id(124718);

  script_name(english:"Oracle Solaris Critical Patch Update : ldoms (SRU11_2_11_5_0)");
  script_summary(english:"Check for the jul2015 CPU and ldoms.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris system is missing a security patch from the July
2015 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"description", value:
"The remote Solaris system is missing necessary patches to address
an unspecified flaw that exists in the LDOM Manager subcomponent of
Oracle VM Server for SPARC. A remote, unauthenticated attacker can
exploit this, via multiple protocols, to cause a denial of service
condition.");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368792.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?591ab328");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=20018633.1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2018633.1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");

pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^ldoms$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldoms");

fix_release = "0.5.11-0.175.2.11.0.5.0";

flag = 0;

if (solaris_check_release(release:fix_release, sru:"11.2.11.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : ldoms\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "ldoms");
