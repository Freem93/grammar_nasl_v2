#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-13417.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56386);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/20 21:56:28 $");

  script_cve_id("CVE-2011-3365");
  script_bugtraq_id(49925);
  script_xref(name:"FEDORA", value:"2011-13417");

  script_name(english:"Fedora 16 : PyKDE4-4.7.1-2.fc16 / akonadi-1.6.1-1.fc16 / blinken-4.7.1-2.fc16 / cantor-4.7.1-2.fc16 / etc (2011-13417)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE Workspaces, Applications, and Development Platform 4.7.1 bugfix
release, see also: http://kde.org/announcements/announce-4.7.1.php

This batch also includes split packaging for kdeedu-related rpms.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.7.1.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=717115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=723987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=732830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=739642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=740676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=743056"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067219.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f33c8fa9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067220.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd18caca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067221.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b160da1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c12e341"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1f02f52"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?913c015e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92be9b2e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4379a2a9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067227.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2819c26"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7505578"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?624de032"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067230.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?822a756c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067231.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b61c4793"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067232.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8191a152"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067233.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9900ca9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dba6042"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4d91086"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067236.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa019934"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2422b1db"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067238.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96136d6c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1b8a1ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98494adb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067241.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7aa5a566"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db37dea9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5a0c0a6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c3d2722"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067245.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3271761b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ca6b407"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a32d8e0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bc851aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52b6557b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00ee765f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067251.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f492f60"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067252.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43c4dd12"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0acfb311"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067254.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da07fa58"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067255.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03cb0682"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067256.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3da564aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067257.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74df96f0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?645965ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f06b5b84"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da60f1dc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?348432d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1480930"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067263.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?592331e8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12189f51"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dab6f199"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f194dbb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c37a29a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d58affbd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e7aacab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?934da0f5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baea07a3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a38ad5fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0207a3eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067275.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67452b64"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067276.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0209b63b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?499f44c6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c635f99c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067279.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be8731b5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdb858a7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5793d33a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24d19f2b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067283.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9718d779"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067284.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8858bfa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067285.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0cfcc04"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067286.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd4d9a9a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067287.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1fc17ce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:PyKDE4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:akonadi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blinken");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cantor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gwenview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kalgebra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kalzium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kanagram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kbruch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcolorchooser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-settings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaccessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-strigi-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-thumbnailers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepimlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeplasma-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgeography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:khangman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kiten");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:klettres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmplot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kross-interpreters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksaneplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kstars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ktouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kturtle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwordquiz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkdcraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkipi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libksane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:marble");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:parley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:shared-desktop-ontologies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokegen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokekde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokeqt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:step");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:svgpart");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"PyKDE4-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"akonadi-1.6.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"blinken-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"cantor-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"gwenview-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kalgebra-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kalzium-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kamera-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kanagram-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kate-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kbruch-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kcolorchooser-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kde-l10n-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kde-settings-4.7-7.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdeaccessibility-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdeadmin-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdeartwork-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdebase-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdebase-runtime-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdebase-workspace-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdeedu-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdegames-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdegraphics-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdegraphics-strigi-analyzer-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdegraphics-thumbnailers-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdelibs-4.7.1-2.fc16.1")) flag++;
if (rpm_check(release:"FC16", reference:"kdemultimedia-4.7.1-4.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdenetwork-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdepim-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdepim-runtime-4.7.1-4.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdepimlibs-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdeplasma-addons-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdesdk-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdetoys-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kdeutils-4.7.1-3.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kgamma-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kgeography-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"khangman-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kig-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kiten-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"klettres-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kmplot-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kolourpaint-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"konsole-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kross-interpreters-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kruler-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"ksaneplugin-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"ksnapshot-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kstars-4.7.1-3.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"ktouch-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kturtle-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"kwordquiz-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"libkdcraw-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"libkdeedu-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"libkexiv2-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"libkipi-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"libksane-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"marble-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"okular-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"oxygen-icon-theme-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"parley-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"rocs-4.7.1-3.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"shared-desktop-ontologies-0.8.0-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"smokegen-4.7.1-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"smokekde-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"smokeqt-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"step-4.7.1-2.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"svgpart-4.7.1-1.fc16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PyKDE4 / akonadi / blinken / cantor / gwenview / kalgebra / kalzium / etc");
}
