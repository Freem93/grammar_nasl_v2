#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_29449. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16911);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:36:49 $");

  script_cve_id("CVE-2002-1265");
  script_xref(name:"HP", value:"emr_na-c00908660");
  script_xref(name:"HP", value:"emr_na-c00951269");
  script_xref(name:"HP", value:"emr_na-c00951288");
  script_xref(name:"HP", value:"emr_na-c00958066");
  script_xref(name:"HP", value:"HPSBUX00215");
  script_xref(name:"HP", value:"HPSBUX00252");
  script_xref(name:"HP", value:"HPSBUX00272");
  script_xref(name:"HP", value:"HPSBUX01020");
  script_xref(name:"HP", value:"SSRT2336");
  script_xref(name:"HP", value:"SSRT2384");
  script_xref(name:"HP", value:"SSRT2439");
  script_xref(name:"HP", value:"SSRT3596");

  script_name(english:"HP-UX PHNE_29449 : s700_800 11.22 ONC/NFS General Release/Performance Patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.22 ONC/NFS General Release/Performance Patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP-UX running RPC services, where the vulnerability
    may be exploited by an unauthorized remote user to
    create a denial of service (DoS). (HPSBUX01020 SSRT2384)

  - Potential buffer overflow in XDR library. (HPSBUX00215
    SSRT2336)

  - Potential buffer overflow in xdrmem_getbytes() and
    related functions. (HPSBUX00252 SSRT2439)

  - The error messages returned by rpc.mountd can be used to
    determine whether a file exists. (HPSBUX00272 SSRT3596)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00958066
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69026abe"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00951269
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5206c4fd"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00908660
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00ac5958"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00951288
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87f2ecde"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_29449 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/08");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/29");
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

if (!hpux_check_ctx(ctx:"11.22"))
{
  exit(0, "The host is not affected since PHNE_29449 applies to a different OS release.");
}

patches = make_list("PHNE_29449", "PHNE_30084");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"NFS.KEY-CORE", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64SLIB", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-ENG-A-MAN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-JPN-E-MAN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-JPN-S-MAN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-KRN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-PRG", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SHLIBS", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CLIENT", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CORE", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-SERVER", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS-SERVER", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CLIENT", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CORE", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-SERVER", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NISPLUS2-CORE", version:"B.11.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
