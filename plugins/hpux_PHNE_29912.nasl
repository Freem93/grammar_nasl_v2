#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_29912. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16855);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/01/14 15:43:28 $");

  script_cve_id("CVE-2003-0681", "CVE-2003-0694");
  script_xref(name:"CERT-CC", value:"2003-25");
  script_xref(name:"HP", value:"emr_na-c01035741");
  script_xref(name:"HP", value:"HPSBUX00281");
  script_xref(name:"HP", value:"SSRT3631");

  script_name(english:"HP-UX PHNE_29912 : HP-UX sendmail, Remote Unauthorized Privileged Access (HPSBUX00281 SSRT3631 rev.11)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.22 sendmail(1m) 8.11.1 patch : 

A potential security vulnerability has been identified with HP-UX
running sendmail, where the vulnerability could be exploited remotely
to gain unauthorized privileged access. References: CERT/CC
CA-2003-25, CAN-2003-0681."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01035741
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ac166f8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_29912 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/16");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
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

if (!hpux_check_ctx(ctx:"11.22"))
{
  exit(0, "The host is not affected since PHNE_29912 applies to a different OS release.");
}

patches = make_list("PHNE_29912");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-RUN", version:"B.11.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
