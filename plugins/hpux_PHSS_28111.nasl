#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_28111. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(17492);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/04/20 00:36:50 $");

  script_cve_id("CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1156");
  script_xref(name:"CERT", value:"240329");
  script_xref(name:"CERT", value:"825353");
  script_xref(name:"CERT", value:"858881");
  script_xref(name:"CERT", value:"91071");
  script_xref(name:"HP", value:"emr_na-c00944288");
  script_xref(name:"HP", value:"HPSBUX00224");
  script_xref(name:"HP", value:"SSRT2393");

  script_name(english:"HP-UX PHSS_28111 : HP-UX Running Apache, Increased Privileges or Denial of Service (DoS) or Execution of Arbitrary Code (HPSBUX00224 SSRT2393 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.5 IWS Update : 

Potential vulnerability regarding ownership permissions of System V
shared memory based scoreboards. (CERT VU#825353, CVE CAN-2002-0839)
Potential cross-site scripting vulnerability in the default error page
when using wildcard DNS. (CERT VU#240329, CVE CAN-2002-0840) Potential
overflows in ab.c which could be exploited by a malicious server.
(CERT VU#858881, CVE CAN-2002-0843) Exposure of CGI source when a POST
request is sent to a location where both DAV and CGI are enabled.
(CERT VU#91071, CVE CAN-2002-1156)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00944288
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d769217"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_28111 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/07");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/05");
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
  exit(0, "The host is not affected since PHSS_28111 applies to a different OS release.");
}

patches = make_list("PHSS_28111", "PHSS_28521", "PHSS_29541", "PHSS_29892", "PHSS_30159", "PHSS_30647", "PHSS_31827", "PHSS_32141", "PHSS_34171", "PHSS_35104", "PHSS_35306", "PHSS_35458", "PHSS_35553");
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
if (hpux_check_patch(app:"VaultTS.VVOS-ADM-RUN", version:"A.04.50")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
