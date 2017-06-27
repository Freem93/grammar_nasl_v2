#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_36193. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(32390);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/03/12 15:37:25 $");

  script_cve_id("CVE-2008-0713");
  script_osvdb_id(45049);
  script_xref(name:"HP", value:"emr_na-c01446326");
  script_xref(name:"HP", value:"HPSBUX02334");
  script_xref(name:"HP", value:"SSRT071403");

  script_name(english:"HP-UX PHNE_36193 : HP-UX Running ftp, Remote Denial of Service (DoS) (HPSBUX02334 SSRT071403 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 ftpd(1M) and ftp(1) patch : 

A potential security vulnerability has been identified with HP-UX
running ftp. The vulnerability could be exploited remotely to create a
Denial of Service (DoS). The Denial of Service (DoS) affects the ftp
server application only."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01446326
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9ff6068"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_36193 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/06");
  script_set_attribute(attribute:"patch_modification_date", value:"2008/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_36193 applies to a different OS release.");
}

patches = make_list("PHNE_36193", "PHNE_38578", "PHNE_38916", "PHNE_40380", "PHNE_41248", "PHNE_41581", "PHNE_42661");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-RUN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
