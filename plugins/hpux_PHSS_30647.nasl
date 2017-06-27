#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_30647. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17070);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2003-0020", "CVE-2004-0079", "CVE-2004-0112", "CVE-2004-0113", "CVE-2004-0174");
  script_xref(name:"HP", value:"emr_na-c00944046");
  script_xref(name:"HP", value:"HPSBUX01019");
  script_xref(name:"HP", value:"HPSBUX01057");
  script_xref(name:"HP", value:"HPSBUX01068");
  script_xref(name:"HP", value:"HPSBUX01069");
  script_xref(name:"HP", value:"SSRT4717");

  script_name(english:"HP-UX PHSS_30647 : s700_800 11.04 Virtualvault 4.5 IWS Update");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.5 IWS Update : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with Apache running on HP-UX where the vulnerability
    could be exploited remotely to create a Denial of
    Service (DoS) or to bypass access restrictions.

  - A potential security vulnerability has been identified
    with HP-UX running Apache where the vulnerability could
    be exploited remotely to create a Denial of Service
    (DoS) or to execute arbitrary code.

  - A potential security vulnerability has been identified
    with Apache running on HP-UX where a buffer overflow
    could be exploited remotely to execute arbitrary code.

  - Two potential security vulnerabilities have been
    identified in OpenSSL by NISCC (224012/1 and 224012/2).
    The Common Vulnerabilities and Exposures project has
    referenced them as the following CAN-2004-0079, and
    CAN-2004-0112. The CERT summary is TA04-078A. 1. The
    do_change_cipher_spec function in OpenSSL allows remote
    attackers to cause a denial of service via a crafted
    SSL/TLS handshake that triggers a null dereference.
    CVE-2004-0079 2. The SSL/TLS handshaking, when using
    Kerberos ciphersuites, does not properly check the
    length of Kerberos tickets during a handshake, which
    allows remote attackers to cause a denial of service via
    a crafted SSL/TLS handshake that causes an out-of-bounds
    read. CVE-2004-0112. (HPSBUX01019 SSRT4717)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00944046
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6195bc72"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_30647 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/01");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
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
  exit(0, "The host is not affected since PHSS_30647 applies to a different OS release.");
}

patches = make_list("PHSS_30647", "PHSS_31827", "PHSS_32141", "PHSS_34171", "PHSS_35104", "PHSS_35306", "PHSS_35458", "PHSS_35553");
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
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
