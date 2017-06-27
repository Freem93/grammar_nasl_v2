#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-13499.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69153);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 21:12:41 $");

  script_cve_id("CVE-2013-2126");
  script_xref(name:"FEDORA", value:"2013-13499");

  script_name(english:"Fedora 17 : analitza-4.10.5-1.fc17 / ark-4.10.5-1.fc17 / audiocd-kio-4.10.5-1.fc17 / etc (2013-13499)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?960a3870"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02879a10"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcf3fa04"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c7ac53"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2eada677"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?099158c7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46c363e5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f718669"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f54b6a5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9124bc47"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d90990aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91da1ab6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112736.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0562bde6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d16afa7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d886159f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112739.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?674a9f30"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112740.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f06c69a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112741.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a0187b1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112742.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49d56683"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112743.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0d1424c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112744.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ee7dff9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112745.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58fcd2b1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112746.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff1d75f0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0177eaf2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65b50044"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112749.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ce1556f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112750.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d611f5f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112751.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4a42f71"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112752.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8ecd631"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ac31b99"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112754.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ce22c56"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112755.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33a7eb8a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112756.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74ca16e1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112757.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?213e51ee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112758.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89c30663"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112759.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f99d7892"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112760.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a494e501"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112761.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb724483"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112762.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81f84b9d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112763.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?540704fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112764.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ea4bc78"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3414aeca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112766.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb799a1a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112767.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9e01d65"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b46e99e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cbf92af"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112770.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d8927cb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112771.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1cfe91e1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112772.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a104e14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58ac993c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112774.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?716270f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112775.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f7e6f3b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112776.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7faeeee3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112777.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00b8d358"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112778.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e97938e1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112779.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baa8b6f2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112780.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a015906"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d511284"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a028ef96"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112783.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b2b461e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9b44262"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112785.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?054cb0df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112786.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ad4ea41"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112787.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a5d69a8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112788.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74d9f907"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112789.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d0003a8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112790.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?305c0299"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112791.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed1a01ed"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112792.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01b062f8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112793.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4cc8686"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112794.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?042519fb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112795.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?830dac8f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112796.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b019055f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112797.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f109c5ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112798.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24b6424e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112799.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0cd4192"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1822744d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112801.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74f31de0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f53d1649"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112803.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c28506f9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112804.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d8ee681"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112805.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b22570ac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112806.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4ccac3b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b97dc6fb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112808.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63ec8c51"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112809.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d62e417"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112810.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95520f28"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb78282c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112812.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f69a8e67"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ca17c49"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112814.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a22fe49"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112815.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56cd9f27"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112816.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?887b2a9a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112817.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13529524"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112818.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9e96c8c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112819.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c773d30"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112820.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96e08fee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9288697"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70562205"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8c8e52a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112824.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7f89cd3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112825.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8371f421"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77f3005a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112827.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a75e3d16"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112828.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42d3e299"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f14ac8e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33d2efdb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2207dc3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65de802e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73570661"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a1871db"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98202195"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e6b768f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7adc67f5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?114ef0dc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112839.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f07f2869"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3acbf9b7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b339785"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07f58d25"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13ca6030"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3114d41e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72cca637"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8cc8913"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f504ad0a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53ce984c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112849.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?191f8654"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0fa64f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112851.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d10b831e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f44cd23a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112853.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4159b50c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112854.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee2507d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112855.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7c9e0d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112856.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28f414db"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112857.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c00eab2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112858.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82fe42fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd7926e6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1ddc178"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d4dd809"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52124c3c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cdde346"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34379581"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112865.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5ce6e58"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112866.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f50b7117"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/31");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"analitza-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ark-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"audiocd-kio-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"blinken-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"bomber-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"bovo-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"cantor-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"dragon-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"filelight-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"granatier-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"gwenview-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"jovie-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"juk-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kaccessible-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kactivities-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kajongg-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kalgebra-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kalzium-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kamera-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kanagram-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kapman-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kate-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"katomic-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kblackbox-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kblocks-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kbounce-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kbreakout-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kbruch-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kcalc-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kcharselect-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kcolorchooser-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-base-artwork-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-baseapps-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-print-manager-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-runtime-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-wallpapers-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-workspace-4.10.5-3.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeaccessibility-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeadmin-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeartwork-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdebindings-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeedu-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegames-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-mobipocket-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-strigi-analyzer-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-thumbnailers-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdelibs-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdemultimedia-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdenetwork-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdepim-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdepim-runtime-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdepimlibs-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeplasma-addons-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdesdk-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdetoys-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeutils-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdf-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdiamond-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kfloppy-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kfourinline-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgamma-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgeography-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgoldrunner-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgpg-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"khangman-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kig-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kigo-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"killbots-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kimono-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kiriki-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kiten-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kjumpingcube-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"klettres-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"klickety-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"klines-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmag-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmahjongg-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmines-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmix-4.10.5-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmousetool-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmouth-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmplot-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"knavalbattle-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"knetwalk-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kolf-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kollision-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kolourpaint-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"konquest-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"konsole-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kpat-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kremotecontrol-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kreversi-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kross-interpreters-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kruler-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksaneplugin-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kscd-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kshisen-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksirk-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksnakeduel-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksnapshot-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kspaceduel-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksquares-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kstars-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksudoku-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ktimer-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ktouch-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ktuberling-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kturtle-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kubrick-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kwallet-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kwordquiz-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkcddb-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkcompactdisc-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkdcraw-4.10.5-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkdeedu-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkdegames-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkexiv2-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkipi-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkmahjongg-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libksane-4.10.5-3.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"lskat-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"marble-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"nepomuk-core-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"nepomuk-widgets-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"okular-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"oxygen-icon-theme-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"pairs-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"palapeli-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"parley-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"picmi-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"pykde4-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"qyoto-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"rocs-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ruby-korundum-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ruby-qt-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"smokegen-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"smokekde-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"smokeqt-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"step-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"superkaramba-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"svgpart-4.10.5-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"sweeper-4.10.5-2.fc17")) flag++;


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
