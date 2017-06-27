#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_30645. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17530);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2003-0020", "CVE-2004-0079", "CVE-2004-0112", "CVE-2004-0113", "CVE-2004-0174");
  script_xref(name:"HP", value:"emr_na-c00944046");
  script_xref(name:"HP", value:"HPSBUX01019");
  script_xref(name:"HP", value:"SSRT4717");

  script_name(english:"HP-UX PHSS_30645 : HP-UX Running Apache, Remote Denial of Service (DoS) (HPSBUX01019 SSRT4717 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.6 OWS update : 

Two potential security vulnerabilities have been identified in OpenSSL
by NISCC (224012/1 and 224012/2). The Common Vulnerabilities and
Exposures project has referenced them as the following CAN-2004-0079,
and CAN-2004-0112. The CERT summary is TA04-078A. 1. The
do_change_cipher_spec function in OpenSSL allows remote attackers to
cause a denial of service via a crafted SSL/TLS handshake that
triggers a null dereference. CVE-2004-0079 2. The SSL/TLS handshaking,
when using Kerberos ciphersuites, does not properly check the length
of Kerberos tickets during a handshake, which allows remote attackers
to cause a denial of service via a crafted SSL/TLS handshake that
causes an out-of-bounds read. CVE-2004-0112."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00944046
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6195bc72"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_30645 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/21");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_30645 applies to a different OS release.");
}

patches = make_list("PHSS_30645", "PHSS_30947", "PHSS_31057", "PHSS_31826", "PHSS_32183", "PHSS_33397", "PHSS_34120", "PHSS_35108", "PHSS_35462", "PHSS_35557");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultTS.VV-CORE-CMN", version:"A.04.60")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-GUI", version:"A.04.60")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-JAVA", version:"A.04.60")) flag++;
if (hpux_check_patch(app:"VaultWS.WS-CORE", version:"A.04.60")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
