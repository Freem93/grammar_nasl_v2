#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_28685. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17003);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/04/20 00:36:51 $");

  script_cve_id("CVE-2003-0078");
  script_xref(name:"HP", value:"HPSBUX0301");
  script_xref(name:"HP", value:"HPSBUX0303");
  script_xref(name:"HP", value:"SSRT3467");
  script_xref(name:"HP", value:"SSRT3521");

  script_name(english:"HP-UX PHSS_28685 : s700_800 11.04 Virtualvault 4.5 OWS update");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.5 OWS update : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A remotely exploitable potential vulnerability has been
    reported in CAN-2003-0078.

  - #1 A defect in the Java(TM) Virtual Machine may allow
    illegal access to protected fields or methods of an
    object. #2 The Java(TM) Secure Socket Extension (JSSE)
    may incorrectly validate the digital certificate of a
    web site. In addition, the Java Plug-in and Java Web
    Start may incorrectly validate the digital certificates
    of signed JAR files."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_28685 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/07/29");
  script_set_attribute(attribute:"patch_modification_date", value:"2003/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_28685 applies to a different OS release.");
}

patches = make_list("PHSS_28685", "PHSS_29545", "PHSS_29690", "PHSS_30160", "PHSS_30648", "PHSS_31828", "PHSS_32184", "PHSS_33396", "PHSS_34119", "PHSS_35107", "PHSS_35461", "PHSS_35556");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultTS.VV-CORE-CMN", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-GUI", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-JAVA", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-JK", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultWS.WS-CORE", version:"A.04.50")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
