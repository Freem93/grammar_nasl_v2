#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_35483. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(26133);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2002-1337", "CVE-2003-0161", "CVE-2003-0681", "CVE-2003-0694", "CVE-2006-0058", "CVE-2007-2246");
  script_bugtraq_id(6991);
  script_osvdb_id(24037, 35301);
  script_xref(name:"CERT-CC", value:"2003-07");
  script_xref(name:"CERT-CC", value:"2003-12");
  script_xref(name:"CERT-CC", value:"2003-25");
  script_xref(name:"CERT", value:"834865");
  script_xref(name:"HP", value:"emr_na-c00629555");
  script_xref(name:"HP", value:"emr_na-c00841370");
  script_xref(name:"HP", value:"emr_na-c00958338");
  script_xref(name:"HP", value:"emr_na-c00958571");
  script_xref(name:"HP", value:"emr_na-c01035741");
  script_xref(name:"HP", value:"HPSBUX00246");
  script_xref(name:"HP", value:"HPSBUX00253");
  script_xref(name:"HP", value:"HPSBUX00281");
  script_xref(name:"HP", value:"HPSBUX02108");
  script_xref(name:"HP", value:"HPSBUX02183");
  script_xref(name:"HP", value:"SSRT061133");
  script_xref(name:"HP", value:"SSRT061243");
  script_xref(name:"HP", value:"SSRT3469");
  script_xref(name:"HP", value:"SSRT3531");
  script_xref(name:"HP", value:"SSRT3631");

  script_name(english:"HP-UX PHNE_35483 : s700_800 11.00 sendmail(1M) 8.9.3 patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 sendmail(1M) 8.9.3 patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP-UX running sendmail, where the vulnerability may
    be exploited remotely to gain unauthorized access and
    create a Denial of Service (DoS). References: CERT
    CA-2003-07, CAN-2002-1337. (HPSBUX00246 SSRT3469)

  - A vulnerability has been identified in sendmail which
    may allow a remote attacker to execute arbitrary code.
    References: CVE-2006-0058, US-CERT VU#834865.
    (HPSBUX02108 SSRT061133)

  - A potential security vulnerability has been identified
    with HP-UX running sendmail, where the vulnerability
    could be exploited remotely to gain unauthorized
    privileged access. References: CERT/CC CA-2003-25,
    CAN-2003-0681. (HPSBUX00281 SSRT3631)

  - A potential security vulnerability has been identified
    with HP-UX sendmail, where the vulnerability may be
    exploited remotely to gain unauthorized access or create
    a denial of service (DoS). References: CERT CA-2003-12.
    (HPSBUX00253 SSRT3531)

  - A potential security vulnerability has been identified
    with HP-UX running sendmail. This vulnerability could
    allow a remote user to cause a Denial of Service (DoS).
    (HPSBUX02183 SSRT061243)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00958338
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e44f628"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00958571
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b715e4f4"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01035741
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ac166f8"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00629555
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f41ededc"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00841370
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b002323"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_35483 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/03");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_35483 applies to a different OS release.");
}

patches = make_list("PHNE_35483");
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
