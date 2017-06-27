#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_33412. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(20803);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2005-2993");
  script_osvdb_id(19586, 22663);
  script_xref(name:"HP", value:"emr_na-c00592668");
  script_xref(name:"HP", value:"HPSBUX02092");
  script_xref(name:"HP", value:"SSRT5971");

  script_name(english:"HP-UX PHNE_33412 : HP-UX Running ftpd Remote Denial of Service (DoS) (HPSBUX02092 SSRT5971 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 ftpd(1M) and ftp(1) patch : 

A potential security vulnerability has been identified with HP-UX
running ftpd. The vulnerability could be exploited by a remote
unauthorized user to cause ftpd to become unresponsive, leading to a
Denial fo Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00592668
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45d34ec8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_33412 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/17");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHNE_33412 applies to a different OS release.");
}

patches = make_list("PHNE_33412", "PHNE_34544", "PHNE_36129", "PHNE_36192", "PHNE_38458", "PHNE_40774");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:hpux_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
