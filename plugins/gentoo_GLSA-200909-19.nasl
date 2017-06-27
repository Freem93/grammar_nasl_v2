#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200909-19.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(41023);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-2957", "CVE-2009-2958");
  script_bugtraq_id(36120);
  script_osvdb_id(57592, 57593);
  script_xref(name:"GLSA", value:"200909-19");

  script_name(english:"GLSA-200909-19 : Dnsmasq: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200909-19
(Dnsmasq: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in the TFTP functionality
    included in Dnsmasq:
    Pablo Jorge and Alberto Solino
    discovered a heap-based buffer overflow (CVE-2009-2957).
    An
    anonymous researcher reported a NULL pointer reference
    (CVE-2009-2958).
  
Impact :

    A remote attacker in the local network could exploit these
    vulnerabilities by sending specially crafted TFTP requests to a machine
    running Dnsmasq, possibly resulting in the remote execution of
    arbitrary code with the privileges of the user running the daemon, or a
    Denial of Service. NOTE: The TFTP server is not enabled by default.
  
Workaround :

    You can disable the TFTP server either at buildtime by not enabling the
    'tftp' USE flag, or at runtime. Make sure '--enable-tftp' is not set in
    the DNSMASQ_OPTS variable in the /etc/conf.d/dnsmasq file and
    'enable-tftp' is not set in /etc/dnsmasq.conf, either of which would
    enable TFTP support if it is compiled in."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200909-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Dnsmasq users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/dnsmasq-2.5.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-dns/dnsmasq", unaffected:make_list("ge 2.5.0"), vulnerable:make_list("lt 2.5.0"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Dnsmasq");
}
