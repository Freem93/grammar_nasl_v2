#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_34123. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21107);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2005-1268", "CVE-2005-2088", "CVE-2005-2491", "CVE-2005-2728");
  script_bugtraq_id(14106, 14366, 14620);
  script_osvdb_id(18286, 18906, 18977);
  script_xref(name:"HP", value:"emr_na-c00555254");
  script_xref(name:"HP", value:"HPSBUX02074");
  script_xref(name:"HP", value:"SSRT051251");

  script_name(english:"HP-UX PHSS_34123 : Apache-based Web Server on HP-UX mod_ssl, proxy_http, Remote Execution of Arbitrary Code, Denial of Service (DoS), and Unauthorized Access (HPSBUX02074 SSRT051251 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.7 OWS (Apache 2.x) update : 

Potential security vulnerabilities have been identified with Apache
running on HP-UX. These vulnerability could be exploited remotely to
allow execution of arbitrary code, Denial of Service (DoS), or
unauthorized access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00555254
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c4fcb93"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_34123 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/03");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/26");
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
  exit(0, "The host is not affected since PHSS_34123 applies to a different OS release.");
}

patches = make_list("PHSS_34123", "PHSS_34932", "PHSS_35436");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultDOC.VV-HTML-MAN", version:"A.04.70")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-GUI", version:"A.04.70")) flag++;
if (hpux_check_patch(app:"VaultWS.WS-CORE", version:"A.04.70")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
