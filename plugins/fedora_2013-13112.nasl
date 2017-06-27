#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-13112.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69027);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 21:02:58 $");

  script_cve_id("CVE-2013-2126");
  script_xref(name:"FEDORA", value:"2013-13112");

  script_name(english:"Fedora 18 : analitza-4.10.5-1.fc18 / ark-4.10.5-1.fc18 / audiocd-kio-4.10.5-1.fc18 / etc (2013-13112)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE released updates for its Workspaces, Applications, and Development
Platform. These updates are the last in a series of monthly
stabilization updates to the 4.10 series. 4.10.5 updates bring many
bugfixes on top of the latest edition in the 4.10 series and are
recommended updates for everyone running 4.10.4 or earlier versions.
See also: http://kde.org/announcements/announce-4.10.5.php

Fix for CVE-2013-2126, double-free flaw when handling damaged
full-color in Foveon and sRAW files

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.10.5.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=970713"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acf3e24a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112263.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca6df63f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?264e3006"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15eff0f8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e977cc29"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06d4b03f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be05928c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78b39f72"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbba8e53"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4e4a988"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d265216"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e566dc5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ecc0860"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112275.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08905dfc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112276.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70e8990a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55913a45"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fd92fde"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112279.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5c0ad58"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f2d99f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b240bfd3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112282.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9216fd86"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112283.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6068358"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112284.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8d3fde0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112285.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37d3144a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112286.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?099e4481"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112287.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6047351"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b98091a2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112289.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52cd331f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112290.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0febdc9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbcdedaf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47f153e3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16e1bacc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112294.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?370f218b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94ba8a0c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112296.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f279f73a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112297.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a886d6b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112298.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e120d8cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112299.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?486289c1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80568239"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112301.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39c6ed3c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112302.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b3cb5a8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112303.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50b58ff3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112304.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ff9b09c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112305.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?587c083c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f30bf3a8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14aa37f8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112308.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?992458c3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1156093"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90d1a8fa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112311.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dee9a78"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112312.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6d382da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dc125d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112314.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?312ac18b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112315.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95236bf4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112316.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f4bd58a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112317.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dcf1d48"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112318.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5de105a9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112319.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8fe99c1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112320.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4daea6f5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7770dd48"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112322.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3e02ff4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112323.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b9f3770"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?207b90fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc472ab0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112326.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6af472d1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112327.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dafd2d07"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112328.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0417355b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112329.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b490ffa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26239391"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112331.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecbcfa66"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07a564d9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?129309e1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a52fc319"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3228635b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcee8621"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58df7375"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc917e16"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dce5b59b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12ad0b77"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60980f6e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa9392bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?695b2083"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03819f7f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112345.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd27a80a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112346.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35e548e5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b38040a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?849b7086"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1be0684"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?759804ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112351.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b3ab32c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?303228cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ea65b58"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112354.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65c0617a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112355.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f011dbfe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15ff3df9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d7e464a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112358.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c22ffc0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112359.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91524316"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112360.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?926e14a8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112361.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?947d4c90"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112362.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?683317a7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112363.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5082e1d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112364.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f517ef4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2fa00ba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112366.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4612eb4b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8af633b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8662d4f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112369.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f45833d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112370.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?753434b9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70520190"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112372.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9bf9723"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112373.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43eca8d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112374.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6527743d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0edf5df3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112376.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86e81014"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112377.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6de7e31"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112378.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?356d41aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112379.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89cb8b26"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112380.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfd1dad2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112381.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75f9b188"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112382.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe7b27dc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8defda1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112384.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43e72ac4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?047b1653"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112386.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f3ed254"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112387.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd92bc85"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112388.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19a72a12"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?452cba13"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53548778"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112391.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73223118"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e988795"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112393.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9371a66b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112394.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52ddcd51"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?291377c1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62e0f167"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112397.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42f026fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112398.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6338aab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112399.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9591d573"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112400.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66b4e6a6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a133d95a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c465dff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?832b1f8a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0547a91c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112405.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df5b77ec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:analitza");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:audiocd-kio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blinken");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bomber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bovo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cantor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:filelight");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:granatier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gwenview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jovie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:juk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kaccessible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kactivities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kajongg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kalgebra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kalzium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kanagram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kapman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:katomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kblackbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kblocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kbounce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kbreakout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kbruch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcharselect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcolorchooser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-base-artwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-baseapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-print-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-wallpapers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaccessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-mobipocket");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdiamond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kfloppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kfourinline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgeography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgoldrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:khangman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kigo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:killbots");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kimono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kiriki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kiten");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kjumpingcube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:klettres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:klickety");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:klines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmahjongg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmousetool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmouth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmplot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knavalbattle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knetwalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kolf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kollision");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:konquest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kpat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kremotecontrol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kreversi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kross-interpreters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksaneplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kshisen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksirk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksnakeduel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kspaceduel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksquares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kstars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksudoku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ktimer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ktouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ktuberling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kturtle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kubrick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwallet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwordquiz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkcddb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkcompactdisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkdcraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkipi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkmahjongg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libksane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lskat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:marble");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nepomuk-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nepomuk-widgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pairs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:palapeli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:parley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:picmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pykde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qyoto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-korundum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokegen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokekde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokeqt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:step");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:superkaramba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:svgpart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sweeper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"analitza-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ark-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"audiocd-kio-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"blinken-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"bomber-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"bovo-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"cantor-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"dragon-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"filelight-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"granatier-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"gwenview-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"jovie-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"juk-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kaccessible-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kactivities-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kajongg-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kalgebra-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kalzium-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kamera-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kanagram-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kapman-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kate-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"katomic-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kblackbox-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kblocks-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kbounce-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kbreakout-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kbruch-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kcalc-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kcharselect-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kcolorchooser-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-base-artwork-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-baseapps-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-l10n-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-print-manager-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-runtime-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-wallpapers-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-workspace-4.10.5-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeaccessibility-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeadmin-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeartwork-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdebindings-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeedu-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegames-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-mobipocket-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-strigi-analyzer-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-thumbnailers-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdelibs-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdemultimedia-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdenetwork-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdepim-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdepim-runtime-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdepimlibs-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeplasma-addons-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdesdk-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdetoys-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeutils-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdf-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdiamond-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kfloppy-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kfourinline-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgamma-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgeography-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgoldrunner-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgpg-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"khangman-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kig-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kigo-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"killbots-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kimono-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kiriki-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kiten-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kjumpingcube-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"klettres-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"klickety-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"klines-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmag-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmahjongg-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmines-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmix-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmousetool-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmouth-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmplot-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"knavalbattle-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"knetwalk-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kolf-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kollision-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kolourpaint-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"konquest-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"konsole-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kpat-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kremotecontrol-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kreversi-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kross-interpreters-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kruler-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksaneplugin-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kscd-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kshisen-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksirk-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksnakeduel-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksnapshot-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kspaceduel-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksquares-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kstars-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksudoku-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ktimer-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ktouch-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ktuberling-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kturtle-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kubrick-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kwallet-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kwordquiz-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkcddb-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkcompactdisc-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkdcraw-4.10.5-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkdeedu-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkdegames-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkexiv2-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkipi-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkmahjongg-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libksane-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"lskat-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"marble-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nepomuk-core-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nepomuk-widgets-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"okular-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"oxygen-icon-theme-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"pairs-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"palapeli-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"parley-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"picmi-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"pykde4-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"qyoto-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"rocs-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ruby-korundum-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ruby-qt-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"smokegen-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"smokekde-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"smokeqt-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"step-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"superkaramba-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"svgpart-4.10.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"sweeper-4.10.5-2.fc18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "analitza / ark / audiocd-kio / blinken / bomber / bovo / cantor / etc");
}
