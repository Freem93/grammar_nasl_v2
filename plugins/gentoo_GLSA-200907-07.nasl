#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200907-07.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39778);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-1438", "CVE-2009-1513");
  script_bugtraq_id(30801);
  script_osvdb_id(53801, 54109);
  script_xref(name:"GLSA", value:"200907-07");

  script_name(english:"GLSA-200907-07 : ModPlug: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200907-07
(ModPlug: User-assisted execution of arbitrary code)

    Two vulnerabilities have been reported in ModPlug:
    dummy reported an integer overflow in the CSoundFile::ReadMed()
    function when processing a MED file with a crafted song comment or song
    name, which triggers a heap-based buffer overflow (CVE-2009-1438).
    Manfred Tremmel and Stanislav Brabec reported a buffer overflow in the
    PATinst() function when processing a long instrument name
    (CVE-2009-1513).
    The GStreamer Bad plug-ins (gst-plugins-bad) before 0.10.11 built a
    vulnerable copy of ModPlug.
  
Impact :

    A remote attacker could entice a user to read specially crafted files,
    possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200907-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ModPlug users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/libmodplug-0.8.7'
    gst-plugins-bad 0.10.11 and later versions do not include the ModPlug
    plug-in (it has been moved to media-plugins/gst-plugins-modplug). All
    gst-plugins-bad users should upgrade to the latest version and install
    media-plugins/gst-plugins-modplug:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gst-plugins-bad-0.10.11'
    # emerge --ask --verbose 'media-plugins/gst-plugins-modplug'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libmodplug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/13");
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

if (qpkg_check(package:"media-libs/libmodplug", unaffected:make_list("ge 0.8.7"), vulnerable:make_list("lt 0.8.7"))) flag++;
if (qpkg_check(package:"media-libs/gst-plugins-bad", unaffected:make_list("ge 0.10.11"), vulnerable:make_list("lt 0.10.11"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ModPlug");
}
