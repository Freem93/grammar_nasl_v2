#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200610-15.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22930);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2006-4345", "CVE-2006-4346", "CVE-2006-5444", "CVE-2006-5445");
  script_osvdb_id(28215, 28216, 29972, 29973);
  script_xref(name:"GLSA", value:"200610-15");

  script_name(english:"GLSA-200610-15 : Asterisk: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200610-15
(Asterisk: Multiple vulnerabilities)

    Asterisk contains buffer overflows in channels/chan_mgcp.c from the
    MGCP driver and in channels/chan_skinny.c from the Skinny channel
    driver for Cisco SCCP phones. It also dangerously handles
    client-controlled variables to determine filenames in the Record()
    function. Finally, the SIP channel driver in channels/chan_sip.c could
    use more resources than necessary under unspecified circumstances.
  
Impact :

    A remote attacker could execute arbitrary code by sending a crafted
    audit endpoint (AUEP) response, by sending an overly large Skinny
    packet even before authentication, or by making use of format strings
    specifiers through the client-controlled variables. An attacker could
    also cause a Denial of Service by resource consumption through the SIP
    channel driver.
  
Workaround :

    There is no known workaround for the format strings vulnerability at
    this time. You can comment the lines in /etc/asterisk/mgcp.conf,
    /etc/asterisk/skinny.conf and /etc/asterisk/sip.conf to deactivate the
    three vulnerable channel drivers. Please note that the MGCP channel
    driver is disabled by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200610-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.2.13'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/asterisk", unaffected:make_list("ge 1.2.13", "rge 1.0.12"), vulnerable:make_list("lt 1.2.13", "lt 1.0.12"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Asterisk");
}
