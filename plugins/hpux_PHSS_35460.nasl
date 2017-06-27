#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_35460. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(23718);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2005-3352", "CVE-2006-3352", "CVE-2006-3747", "CVE-2006-4339");
  script_bugtraq_id(19204, 19849);
  script_xref(name:"HP", value:"emr_na-c00794047");
  script_xref(name:"HP", value:"emr_na-c00794048");
  script_xref(name:"HP", value:"HPSBUX02164");
  script_xref(name:"HP", value:"HPSBUX02165");
  script_xref(name:"HP", value:"SSRT061265");
  script_xref(name:"HP", value:"SSRT061266");

  script_name(english:"HP-UX PHSS_35460 : s700_800 11.04 Virtualvault 4.7 IWS update");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.7 IWS update : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Two potential security vulnerabilities have been
    reported in HP-UX VirtualVault Apache HTTP server
    versions prior to Apache 1.3.37 that may allow a Denial
    of Service (DoS) attack and execution of arbitrary code.
    (HPSBUX02164 SSRT061265)

  - A security vulnerability has been identified in OpenSSL
    used in HP VirtualVault 4.7, 4.6, 4.5 and HP WebProxy
    that may allow remote unauthorized access. (HPSBUX02165
    SSRT061266)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00794047
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cc8e52a"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00794048
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e53f82c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_35460 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Module mod_rewrite LDAP Protocol Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_35460 applies to a different OS release.");
}

patches = make_list("PHSS_35460", "PHSS_35555");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultTS.VV-CORE-CMN", version:"A.04.70")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS", version:"A.04.70")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
