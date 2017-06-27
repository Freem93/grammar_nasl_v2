#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_27656. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17484);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/04/20 00:36:50 $");

  script_cve_id("CVE-2002-0658");
  script_xref(name:"CERT-CC", value:"2002-21");
  script_xref(name:"HP", value:"HPSBUX0209");

  script_name(english:"HP-UX PHSS_27656 : HPSBUX0209-217 Sec. Vulnerability in Apache OpenSSL (rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Webproxy server 2.0 update : 

Remotely exploitable potential vulnerabilities have been reported in
CA-2002-21 and CVE-2002-0658."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_27656 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/14");
  script_set_attribute(attribute:"patch_modification_date", value:"2002/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
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
  exit(0, "The host is not affected since PHSS_27656 applies to a different OS release.");
}

patches = make_list("PHSS_27656", "PHSS_27834", "PHSS_29230", "PHSS_29547", "PHSS_29894", "PHSS_30650", "PHSS_30949", "PHSS_31829", "PHSS_32363", "PHSS_33788", "PHSS_34204", "PHSS_35110");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"HP_Webproxy.HPWEB-PX-CORE", version:"A.02.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
