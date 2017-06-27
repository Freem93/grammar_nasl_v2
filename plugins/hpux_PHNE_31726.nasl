#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_31726. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16912);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2013/04/20 00:36:49 $");

  script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
  script_xref(name:"HP", value:"emr_na-c00901847");
  script_xref(name:"HP", value:"HPSBUX00290");
  script_xref(name:"HP", value:"SSRT3622");

  script_name(english:"HP-UX PHNE_31726 : HP-UX Running BIND v920, Remote Denial of Service (DoS) (HPSBUX00290 SSRT3622 rev.5)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Bind 9.2.0 components : 

1. Certain ASN.1 encodings that are rejected as invalid by the parser
can trigger a bug in the deallocation of the corresponding data
structure, corrupting the stack. This can be used as a denial of
service attack. It is currently unknown whether this can be exploited
to run malicious code. This issue does not affect OpenSSL 0.9.6. More
details are available at: CVE-2003-0545 2. Unusual ASN.1 tag values
can cause an out of bounds read under certain circumstances, resulting
in a denial of service vulnerability. More details are available at:
CVE-2003-0543 CVE-2003-0544 3. A malformed public key in a certificate
will crash the verify code if it is set to ignore public key decoding
errors. Exploitation of an affected application would result in a
denial of service vulnerability. 4. Due to an error in the SSL/TLS
protocol handling, a server will parse a client certificate when one
is not specifically requested."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00901847
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e1604c4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_31726 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/22");
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
  exit(0, "The host is not affected since PHNE_31726 applies to a different OS release.");
}

patches = make_list("PHNE_31726", "PHNE_32443", "PHNE_34226", "PHNE_35920", "PHNE_36219", "PHNE_36973", "PHNE_37548", "PHNE_37865", "PHNE_40089", "PHNE_40339", "PHNE_41721", "PHNE_42727", "PHNE_43096", "PHNE_43278", "PHNE_43369");
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
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
