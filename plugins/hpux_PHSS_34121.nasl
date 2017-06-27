#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_34121. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(21106);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/03/19 14:42:13 $");

  script_cve_id("CVE-2005-2088");
  script_bugtraq_id(14106);
  script_osvdb_id(17738);
  script_xref(name:"HP", value:"emr_na-c00612828");
  script_xref(name:"HP", value:"HPSBUX02101");
  script_xref(name:"HP", value:"SSRT051128");

  script_name(english:"HP-UX PHSS_34121 : HP-UX VirtualVault running Apache 1.3.X Remote Unauthorized Access (HPSBUX02101 SSRT051128 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.7 (Apache 1.x) OWS update : 

A security vulnerability has been identified in Apache HTTP server
versions prior to Apache 1.3.34 that may allow HTTP Request
Splitting/Spoofing attacks, resulting in remote unauthorized access.
References: Apache HTTP Server version 1.3.34 announcement."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00612828
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e43753d4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_34121 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_34121 applies to a different OS release.");
}

patches = make_list("PHSS_34121", "PHSS_35109", "PHSS_35463", "PHSS_35558");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultWS.WS-CORE", version:"A.04.70")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
