#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-10130.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67268);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2013-2120");
  script_bugtraq_id(60216);
  script_xref(name:"FEDORA", value:"2013-10130");

  script_name(english:"Fedora 18 : analitza-4.10.4-1.fc18 / ark-4.10.4-1.fc18 / audiocd-kio-4.10.4-1.fc18 / etc (2013-10130)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"kde 4.10.4 bugfix release, see also:
http://kde.org/announcements/announce-4.10.4.php

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kde.org/announcements/announce-4.10.4.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=969421"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108508.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8f11fe1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8ebe000"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108510.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cffa6336"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab3c31bc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5004f732"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a78d6129"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?145e3487"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63fdefd5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a78c9f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08cb5f58"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?923aec56"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edbebfa3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108520.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f9d43fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f896dbec"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a756de89"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7b098d0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15fb25fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108525.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dd4c32e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?367aef5b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ff85664"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108528.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?143c63ee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108529.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e99c4704"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108530.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19969024"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a2efa21"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108532.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f998093"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108533.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c5cde86"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b33438da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?860d95b8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01b0d7b9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f3c0685"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fd3188f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7509fc6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?393821f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68f23c02"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108542.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51f45af8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108543.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9517b893"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a91f62a0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1bbc870"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93ac659e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108547.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34cae729"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108548.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c1d19e7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108549.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b424be8c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108550.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?917d70c9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?456bac84"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108552.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c9d964f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108553.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27fc08ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108554.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17e38721"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e656191"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5c98891"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37aa0f7d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108558.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7831e7e0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4398bd32"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33eb4061"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?365d0c42"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90e7d420"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108563.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3dca17fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be07947e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108565.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba1604d2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3010600"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108567.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75a7e838"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108568.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce5f9cab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108569.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0abc2624"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cc8481b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108571.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d93dd276"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108572.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0997a14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108573.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecf5c735"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108574.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13e651fa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108575.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2a9aa5f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108576.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bb00b28"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108577.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab5f1fd6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108578.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57ed18f7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108579.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82965cba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108580.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?425324fb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63262493"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108582.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99b3fc9c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108583.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c31a8c44"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108584.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?498f7bf4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108585.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f27f07b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108586.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36199b98"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54a48a8f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc7e6e84"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ab59f8c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4226cf4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b01af2f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77a4a2d0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd458f38"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fbff81d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb913625"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?389d34c2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dac4f75"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?762f1f96"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108599.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edab318b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23fb319b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108601.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1920015"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54f1cf5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108603.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bbb571f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?521d3af9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcbea8e6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108606.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40b57953"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108607.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0eca2ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed460758"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108609.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c430367"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108610.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00abcb23"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108611.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a9fb099"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108612.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0aacf2a2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108613.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e067eadc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce4e1b61"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108615.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbc7fc62"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bc4808e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48f5c8b4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec7d505a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108619.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e877a9b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d2d97c2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108621.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?791125f4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8b8714b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108623.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3366eff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bbec487"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108625.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdf7b268"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108626.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19a15c31"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108627.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a1cff87"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a5446ac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc35a663"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108630.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f282c67f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f85c72d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f32f01a8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b805bab7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108634.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?320972fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774fcf7f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108636.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a1df530"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108637.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b132de35"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108638.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bd731fa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8911635"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108640.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0655facc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?218505c8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4caf00ce"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9374ad11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f07359e4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0e05c68"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f9351fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b60492f7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f0f4e5d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108649.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98a0201e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108650.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7a76c54"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108651.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2b52c51"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC18", reference:"analitza-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ark-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"audiocd-kio-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"blinken-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"bomber-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"bovo-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"cantor-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"dragon-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"filelight-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"granatier-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"gwenview-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"jovie-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"juk-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kaccessible-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kactivities-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kajongg-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kalgebra-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kalzium-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kamera-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kanagram-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kapman-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kate-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"katomic-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kblackbox-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kblocks-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kbounce-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kbreakout-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kbruch-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kcalc-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kcharselect-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kcolorchooser-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-base-artwork-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-baseapps-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-l10n-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-print-manager-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-runtime-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-wallpapers-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kde-workspace-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeaccessibility-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeadmin-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeartwork-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdebindings-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeedu-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegames-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-mobipocket-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-strigi-analyzer-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdegraphics-thumbnailers-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdelibs-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdemultimedia-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdenetwork-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdepim-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdepim-runtime-4.10.4-1.fc18.1")) flag++;
if (rpm_check(release:"FC18", reference:"kdepimlibs-4.10.4-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeplasma-addons-4.10.4-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdesdk-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdetoys-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdeutils-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdf-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kdiamond-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kfloppy-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kfourinline-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgamma-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgeography-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgoldrunner-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kgpg-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"khangman-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kig-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kigo-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"killbots-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kimono-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kiriki-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kiten-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kjumpingcube-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"klettres-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"klickety-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"klines-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmag-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmahjongg-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmines-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmix-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmousetool-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmouth-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kmplot-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"knavalbattle-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"knetwalk-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kolf-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kollision-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kolourpaint-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"konquest-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"konsole-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kpat-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kremotecontrol-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kreversi-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kross-interpreters-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kruler-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksaneplugin-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kscd-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kshisen-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksirk-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksnakeduel-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksnapshot-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kspaceduel-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksquares-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kstars-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ksudoku-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ktimer-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ktouch-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ktuberling-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kturtle-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kubrick-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kwallet-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"kwordquiz-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkcddb-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkcompactdisc-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkdcraw-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkdeedu-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkdegames-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkexiv2-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkipi-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libkmahjongg-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"libksane-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"lskat-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"marble-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nepomuk-core-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"nepomuk-widgets-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"okular-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"oxygen-icon-theme-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"pairs-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"palapeli-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"parley-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"picmi-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"pykde4-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"qyoto-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"rocs-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ruby-korundum-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"ruby-qt-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"smokegen-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"smokekde-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"smokeqt-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"step-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"superkaramba-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"svgpart-4.10.4-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"sweeper-4.10.4-1.fc18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "analitza / ark / audiocd-kio / blinken / bomber / bovo / cantor / etc");
}
