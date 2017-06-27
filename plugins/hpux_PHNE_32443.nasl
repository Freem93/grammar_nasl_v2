#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_32443. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16544);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/04/20 00:36:49 $");

  script_cve_id("CVE-2005-0364");
  script_xref(name:"HP", value:"emr_na-c00897401");
  script_xref(name:"HP", value:"HPSBUX01117");
  script_xref(name:"HP", value:"SSRT4861");

  script_name(english:"HP-UX PHNE_32443 : HP-UX Running BIND v9.2.0, Remote Denial of Service (DoS) (HPSBUX01117 SSRT4861 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Bind 9.2.0 components : 

A potential vulnerability has been identified with HP-UX BIND 9.2.0
which could be exploited by a remote, unauthorized user to create a
Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00897401
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c94e698a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_32443 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/22");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHNE_32443 applies to a different OS release.");
}

patches = make_list("PHNE_32443", "PHNE_34226", "PHNE_35920", "PHNE_36219", "PHNE_36973", "PHNE_37548", "PHNE_37865", "PHNE_40089", "PHNE_40339", "PHNE_41721", "PHNE_42727", "PHNE_43096", "PHNE_43278", "PHNE_43369");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-INETD", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-RUN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
