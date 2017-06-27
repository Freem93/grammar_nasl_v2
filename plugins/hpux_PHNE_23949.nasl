#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_23949. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16577);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2004-1332", "CVE-2005-3296");
  script_osvdb_id(20680);
  script_xref(name:"HP", value:"emr_na-c00542740");
  script_xref(name:"HP", value:"emr_na-c00898886");
  script_xref(name:"HP", value:"HPSBUX00162");
  script_xref(name:"HP", value:"HPSBUX02071");
  script_xref(name:"HP", value:"SSRT051064");
  script_xref(name:"HP", value:"SSRT4883");

  script_name(english:"HP-UX PHNE_23949 : s700_800 11.00 ftpd(1M) and ftp(1) patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 ftpd(1M) and ftp(1) patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential vulnerability has been identified with HP-UX
    running ftpd. The vulnerability could be exploited by a
    remote unauthenticated user to list directories with the
    privileges of the root user. (HPSBUX02071 SSRT051064)

  - ftpd and ftp incorrectly manage buffers. (HPSBUX00162
    SSRT4883)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00898886
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1aba643e"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00542740
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8f47fb9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_23949 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/05/18");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHNE_23949 applies to a different OS release.");
}

patches = make_list("PHNE_23949", "PHNE_29460", "PHNE_30989", "PHNE_33406", "PHNE_34543");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
