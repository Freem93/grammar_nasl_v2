#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201310-12.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70647);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-4631", "CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4636", "CVE-2009-4637", "CVE-2009-4638", "CVE-2009-4639", "CVE-2009-4640", "CVE-2010-3429", "CVE-2010-3908", "CVE-2010-4704", "CVE-2010-4705", "CVE-2011-1931", "CVE-2011-3362", "CVE-2011-3893", "CVE-2011-3895", "CVE-2011-3929", "CVE-2011-3934", "CVE-2011-3935", "CVE-2011-3936", "CVE-2011-3937", "CVE-2011-3940", "CVE-2011-3941", "CVE-2011-3944", "CVE-2011-3945", "CVE-2011-3946", "CVE-2011-3947", "CVE-2011-3949", "CVE-2011-3950", "CVE-2011-3951", "CVE-2011-3952", "CVE-2011-3973", "CVE-2011-3974", "CVE-2011-4351", "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2012-0947", "CVE-2012-2771", "CVE-2012-2772", "CVE-2012-2773", "CVE-2012-2774", "CVE-2012-2775", "CVE-2012-2776", "CVE-2012-2777", "CVE-2012-2778", "CVE-2012-2779", "CVE-2012-2780", "CVE-2012-2781", "CVE-2012-2782", "CVE-2012-2783", "CVE-2012-2784", "CVE-2012-2785", "CVE-2012-2786", "CVE-2012-2787", "CVE-2012-2788", "CVE-2012-2789", "CVE-2012-2790", "CVE-2012-2791", "CVE-2012-2792", "CVE-2012-2793", "CVE-2012-2794", "CVE-2012-2795", "CVE-2012-2796", "CVE-2012-2797", "CVE-2012-2798", "CVE-2012-2799", "CVE-2012-2800", "CVE-2012-2801", "CVE-2012-2802", "CVE-2012-2803", "CVE-2012-2804", "CVE-2012-2805", "CVE-2013-3670", "CVE-2013-3671", "CVE-2013-3672", "CVE-2013-3673", "CVE-2013-3674", "CVE-2013-3675");
  script_bugtraq_id(36465, 46294, 47147, 47602, 49115, 49118, 50642, 50760, 50880, 51720, 53389, 55355, 60476, 60491, 60492, 60494, 60496, 60497);
  script_osvdb_id(58503, 58504, 58505, 58506, 58507, 58508, 58509, 58510, 62327, 62328, 68269, 70650, 70651, 72577, 72579, 74926, 76802, 76803, 77033, 77035, 77289, 77290, 77291, 78090, 78634, 78635, 78636, 78637, 78638, 78639, 78640, 78641, 78642, 78643, 78644, 78645, 78646, 78647, 78648, 82128, 85267, 85268, 85269, 85270, 85271, 85272, 85273, 85274, 85275, 85276, 85277, 85278, 85279, 85280, 85281, 85282, 85283, 85284, 85285, 85286, 85287, 85288, 85289, 85290, 85291, 85292, 85293, 85294, 85295, 85300, 94161, 94162, 94163, 94164, 94165, 94166, 94527, 94528, 94529, 94530, 94531, 94532, 94654, 94666);
  script_xref(name:"GLSA", value:"201310-12");

  script_name(english:"GLSA-201310-12 : FFmpeg: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201310-12
(FFmpeg: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in FFmpeg. Please review
      the CVE identifiers and FFmpeg changelogs referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted media
      file, possibly leading to the execution of arbitrary code with the
      privileges of the user running the application or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://git.videolan.org/?p=ffmpeg.git;a=shortlog;h=refs/heads/release/0.10
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b33cea6d"
  );
  # http://git.videolan.org/?p=ffmpeg.git;a=shortlog;h=refs/heads/release/1.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82b0907f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2011-04/0258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/36760/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://secunia.com/advisories/46134/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201310-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All FFmpeg users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-video/ffmpeg-1.0.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-video/ffmpeg", unaffected:make_list("ge 1.0.7"), vulnerable:make_list("lt 1.0.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "FFmpeg");
}
