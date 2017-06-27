#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200505-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18229);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1456", "CVE-2005-1457", "CVE-2005-1458", "CVE-2005-1459", "CVE-2005-1460", "CVE-2005-1461", "CVE-2005-1462", "CVE-2005-1463", "CVE-2005-1464", "CVE-2005-1465", "CVE-2005-1466", "CVE-2005-1467", "CVE-2005-1468", "CVE-2005-1469", "CVE-2005-1470");
  script_osvdb_id(16093, 16094, 16095, 16096, 16097, 16098, 16099, 16100, 16101, 16102, 16103, 16104, 16105, 16106, 16107, 16108, 16109, 16110, 16111, 16112, 16113, 16114, 16115, 16116, 16117, 16118, 16119, 16120, 16121, 16122, 16123, 16124, 16125, 16126, 16127, 16129, 16130, 16131, 16132, 16133, 16134, 16135, 16136, 16137, 16138, 16139, 16140, 16141, 16142, 16143, 16144, 16145, 16146, 16147, 16148, 16149, 16150, 16151, 16152, 16153, 16269);
  script_xref(name:"GLSA", value:"200505-03");

  script_name(english:"GLSA-200505-03 : Ethereal: Numerous vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200505-03
(Ethereal: Numerous vulnerabilities)

    There are numerous vulnerabilities in versions of Ethereal prior
    to 0.10.11, including:
    The ANSI A and DHCP dissectors are
    vulnerable to format string vulnerabilities.
    The DISTCC,
    FCELS, SIP, ISIS, CMIP, CMP, CMS, CRMF, ESS, OCSP, PKIX1Explitit, PKIX
    Qualified, X.509, Q.931, MEGACO, NCP, ISUP, TCAP and Presentation
    dissectors are vulnerable to buffer overflows.
    The KINK, WSP,
    SMB Mailslot, H.245, MGCP, Q.931, RPC, GSM and SMB NETLOGON dissectors
    are vulnerable to pointer handling errors.
    The LMP, KINK,
    MGCP, RSVP, SRVLOC, EIGRP, MEGACO, DLSw, NCP and L2TP dissectors are
    vulnerable to looping problems.
    The Telnet and DHCP dissectors
    could abort.
    The TZSP, Bittorrent, SMB, MGCP and ISUP
    dissectors could cause a segmentation fault.
    The WSP, 802.3
    Slow protocols, BER, SMB Mailslot, SMB, NDPS, IAX2, RADIUS, SMB PIPE,
    MRDISC and TCAP dissectors could throw assertions.
    The DICOM,
    NDPS and ICEP dissectors are vulnerable to memory handling errors.
    The GSM MAP, AIM, Fibre Channel,SRVLOC, NDPS, LDAP and NTLMSSP
    dissectors could terminate abnormallly.
  
Impact :

    An attacker might be able to use these vulnerabilities to crash
    Ethereal and execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200505-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/ethereal-0.10.11'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"net-analyzer/ethereal", unaffected:make_list("ge 0.10.11"), vulnerable:make_list("lt 0.10.11"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ethereal");
}
