#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_29891. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17508);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");

  script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
  script_xref(name:"CERT", value:"104280");
  script_xref(name:"CERT", value:"255484");
  script_xref(name:"CERT", value:"686224");
  script_xref(name:"CERT", value:"732952");
  script_xref(name:"CERT", value:"935264");
  script_xref(name:"HP", value:"HPSBUX0310");
  script_xref(name:"HP", value:"SSRT3622");

  script_name(english:"HP-UX PHSS_29891 : HPSBUX0310-284 SSRT3622 rev.3 HP-UX Apache HTTP Server Denial of Service,unauthorized access");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.6 TGP update : 

Potential Apache HTTP server vulnerabilities have been reported:
CVE-2003-0545 CVE-2003-0543 CVE-2003-0544 CERT VU#935264 CERT
VU#255484 CERT VU#255484 CERT VU#686224 CERT VU#732952 CERT VU#104280
http://www.openssl.org/news/secadv/20030930.txt."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20030930.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_29891 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/10");
  script_set_attribute(attribute:"patch_modification_date", value:"2004/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_29891 applies to a different OS release.");
}

patches = make_list("PHSS_29891", "PHSS_30646", "PHSS_34165", "PHSS_35480", "PHSS_35559");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultTGP.TGP-CORE", version:"A.04.60")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
