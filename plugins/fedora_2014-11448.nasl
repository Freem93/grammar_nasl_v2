#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-11448.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77937);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:06:08 $");

  script_cve_id("CVE-2014-5033");
  script_xref(name:"FEDORA", value:"2014-11448");

  script_name(english:"Fedora 20 : akonadi-1.13.0-2.fc20 / amor-4.14.1-1.fc20 / analitza-4.14.1-1.fc20 / ark-4.14.1-1.fc20 / etc (2014-11448)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE released updates for its Applications and Development Platform,
the first in a series of monthly stabilization updates to the 4.14
series. This update also includes the latest stable calligra-2.8.6 and
digikam-4.3.0 releases. See also http://kde.org/announcements/4.14/ ,
http://kde.org/announcements/announce-4.14.1.php ,
https://www.calligra.org/news/calligra-2-8-6-released/ ,
https://www.digikam.org/node/718

The update also addresses CVE-2014-5033, fixed in kdelibs ' 4.14.0:
KAuth was calling PolicyKit 1 (polkit) in an insecure way.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/4.14/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.14.1.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1094890"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b518859a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a252844"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef8f4a10"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?153a8387"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fc30846"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f917ff9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad2ddd1b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b8652ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a9d0bd3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca4522ed"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80f43699"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b85978c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4771d573"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c32b8114"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1dbe597"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7395d5b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0913cfa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc9d5c49"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d06d389a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16212af1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138736.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b96cc30"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de6c6c5c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e993943"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138739.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?670e4cb7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138740.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2123b04a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138741.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43969367"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138742.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7206044d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138743.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46591924"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138744.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40a20ec5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138745.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d6fd5cc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138746.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cbb25e3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a0b6e44"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e283ecd2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138749.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf2d6811"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138750.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af01871b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138751.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af91d95a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138752.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f15c8d81"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138753.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e4d12dc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138754.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbd714a5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138755.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee5ad235"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138756.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?349c71a4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138757.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0746419"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138758.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5cc7fdc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138759.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dadb060"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138760.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b997288"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138761.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9f83123"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138762.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d445cdd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138763.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93e29e75"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138764.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e062257"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f181b0b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138766.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbd8d25e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138767.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70995636"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a96ddfb8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3abbfc4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138770.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8098ebc0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138771.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9160704"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138772.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3c400f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88db7340"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138774.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24c5d0c0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138775.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e31c3220"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138776.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcc70153"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138777.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7dbabee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138778.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13b4e399"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138779.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25daa1f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138780.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fee9070"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4642ecd6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7704492"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138783.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?049fb483"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1af39b2c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138785.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4067c53f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138786.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04c1247f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138787.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80f995cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138788.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a9f3862"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138789.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?815ec671"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138790.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccb2279e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138791.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51545f22"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138792.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6351810"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138793.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97657f11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138794.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ce5f92d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138795.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1427af38"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138796.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8333cb50"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138797.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e102ba6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138798.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67601181"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138799.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7764a10e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d401aa4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138801.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8117bb2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d491bee6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138803.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe960c35"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138804.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b1f85e2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138805.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?643110a6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138806.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05f9887f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49fbe200"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138808.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1447e99e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138809.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5fe8720"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138810.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f865dba2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a77d7f9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138812.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce0b7293"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b1dccb2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138814.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08735a07"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138815.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a60e608"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138816.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d327508"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138817.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2802bae8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138818.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f602b0e6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138819.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45c4adb7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138820.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3beeac68"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ce67a87"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0927ac23"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e33dc719"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138824.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?541f75e5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138825.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c41b715"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?444ee8aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138827.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aeb5c5d9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138828.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc0a75ee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa5490c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5476a2de"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20dc171d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7afadda7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6a36014"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33d92ef5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ad23d37"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0fa6cebb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e89575c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38db91a3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138839.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ea5fad7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/138840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78eabe9f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.calligra.org/news/calligra-2-8-6-released/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.digikam.org/node/718"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:akonadi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:amor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:analitza");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:audiocd-kio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:baloo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:baloo-widgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blinken");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:calligra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:calligra-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cantor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:digikam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:filelight");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gwenview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jovie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:juk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kaccessible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kalgebra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kalzium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kanagram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kbruch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcharselect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcolorchooser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kcron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-base-artwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-baseapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-print-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-wallpapers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeaccessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-mobipocket");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-strigi-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdegraphics-thumbnailers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork-filesharing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdenetwork-strigi-analyzers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepimlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeplasma-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kfilemetadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kfloppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgeography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:khangman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kimono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kiten");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:klettres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmousetool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmouth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmplot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kphotoalbum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kqtquickcharts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kremotecontrol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kross-interpreters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksaneplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kstars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksystemlog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kteatime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ktimer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ktouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kturtle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ktux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwalletmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwordquiz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkcddb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkcompactdisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkdcraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkexiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkgapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkipi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkolab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libksane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:marble");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nepomuk-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nepomuk-widgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-icon-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pairs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:parley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pykde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qyoto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-korundum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokegen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokekde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:smokeqt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:step");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subsurface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:superkaramba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:svgpart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sweeper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"akonadi-1.13.0-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"amor-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"analitza-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ark-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"audiocd-kio-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"baloo-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"baloo-widgets-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"blinken-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"calligra-2.8.6-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"calligra-l10n-2.8.6-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"cantor-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"digikam-4.3.0-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"dragon-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"filelight-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"gwenview-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"jovie-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"juk-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kaccessible-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kalgebra-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kalzium-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kamera-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kanagram-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kate-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kbruch-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kcalc-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kcharselect-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kcolorchooser-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kcron-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kde-base-artwork-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kde-baseapps-4.14.1-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kde-l10n-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kde-print-manager-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kde-runtime-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kde-wallpapers-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdeaccessibility-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdeadmin-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdeartwork-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdebindings-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdeedu-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdegraphics-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdegraphics-mobipocket-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdegraphics-strigi-analyzer-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdegraphics-thumbnailers-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdelibs-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdemultimedia-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdenetwork-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdenetwork-filesharing-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdenetwork-strigi-analyzers-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdepim-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdepim-runtime-4.14.1-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdepimlibs-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdeplasma-addons-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdetoys-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdeutils-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdf-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kdnssd-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kfilemetadata-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kfloppy-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kgamma-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kgeography-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kget-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kgpg-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"khangman-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kig-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kimono-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kiten-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"klettres-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kmag-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kmix-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kmousetool-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kmouth-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kmplot-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kolourpaint-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"konsole-4.14.1-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kopete-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kphotoalbum-4.5-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kppp-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kqtquickcharts-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"krdc-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kremotecontrol-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"krfb-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kross-interpreters-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kruler-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ksaneplugin-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kscd-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ksnapshot-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kstars-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ksystemlog-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kteatime-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ktimer-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ktouch-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kturtle-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ktux-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kuser-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kwalletmanager-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"kwordquiz-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkcddb-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkcompactdisc-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkdcraw-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkdeedu-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkexiv2-4.14.1-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkgapi-2.2.0-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkipi-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libkolab-0.5.2-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"libksane-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"marble-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"nepomuk-core-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"nepomuk-widgets-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"okular-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"oxygen-icon-theme-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"pairs-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"parley-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"pykde4-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"qyoto-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"rocs-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ruby-korundum-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"ruby-qt-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"smokegen-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"smokekde-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"smokeqt-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"step-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"subsurface-4.2-1.fc20.1")) flag++;
if (rpm_check(release:"FC20", reference:"superkaramba-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"svgpart-4.14.1-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"sweeper-4.14.1-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "akonadi / amor / analitza / ark / audiocd-kio / baloo / etc");
}
