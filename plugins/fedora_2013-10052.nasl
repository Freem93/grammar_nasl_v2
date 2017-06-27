#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-10052.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67265);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 21:02:56 $");

  script_cve_id("CVE-2013-2120");
  script_xref(name:"FEDORA", value:"2013-10052");

  script_name(english:"Fedora 19 : analitza-4.10.4-1.fc19 / ark-4.10.4-1.fc19 / audiocd-kio-4.10.4-1.fc19 / etc (2013-10052)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?706facbe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108044.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b58b322"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108045.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1bcd313"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a336dbc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?754753b9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bbfd517"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af8c8c65"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dd1974d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108051.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad9cb209"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108052.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee1bba87"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108053.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66381869"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf1d8ad4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5560376"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3463277e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a80c736"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108058.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdbd37a1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ab16e58"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96f8e434"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108061.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81a16f2c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108062.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2365bd0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108063.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faddb62f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108064.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c87b482"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108065.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a09cc099"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108066.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4456e198"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4abf65d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca7c9953"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108069.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6523463"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108070.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?261828e9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108071.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2904eef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108072.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?423521be"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108073.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca7998cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108074.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87847cc9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89c83999"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc511333"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90644a1a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108078.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b78fd2c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19f2b7eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108080.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?537e753a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108081.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85079b09"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108082.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9d622c0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108083.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6df3a028"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?045d9965"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6aee08f2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8502de8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?657dc2b8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51eaeb62"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c50515d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108090.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be55e1c7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04a0ba2e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108092.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b67de472"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55d6b3cb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108094.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac82f793"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108095.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0847086"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108096.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f17289f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108097.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ab95c3c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108098.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a836f2b4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0143df89"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2f60380"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d147fad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45ccb653"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b31b68ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6ae7862"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb9436af"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67bb113d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108107.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8d4a6cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108108.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9412e9c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e72ed301"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108110.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?637a4867"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108111.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?477d4bc0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65b95cde"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108113.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9168e07"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108114.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e8123c3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b65b847"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6fdaafd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2ef873f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71d76629"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22dd46b6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?819730af"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65e6ce11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?509cab32"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe2abcb3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0024d6b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49f14581"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c088bcd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bac21abe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70c838b1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbf595f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108130.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e24ffdc1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?606269a7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8336c3ec"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5a593b5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5b2f1d9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65f0466e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f56870c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ad21b29"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed843c14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108139.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?150c65d8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?241ad9ac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f001abf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0cc9cd2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?569afdd1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d07da4f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66cbeb06"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52057dcb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?068b19cc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ebcfba5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db875c17"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fb02327"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a942acd9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7926e6c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108153.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06a3baf0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32eb9347"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f84a7c14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ce2f628"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a65e0326"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd5b203b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57075580"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a33cdde7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108161.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?896afe2a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d02ab0b0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86ed4292"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108164.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3006811c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a8cfa35"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108166.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80651015"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108167.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3382c90"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108168.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f37c194"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108169.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0deab922"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55aeecc1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?995735ac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2407fd7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9824a8b5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108174.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0da66df4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108175.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?117fbed1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108176.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7810d82"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108177.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c483605"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f5c29ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f44dd14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0242736"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d96ed094"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108182.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5148cc1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8602fd92"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14877bc2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb079ebd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108186.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bb9135b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"analitza-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ark-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"audiocd-kio-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"blinken-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"bomber-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"bovo-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"cantor-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"dragon-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"filelight-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"granatier-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"gwenview-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"jovie-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"juk-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kaccessible-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kactivities-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kajongg-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kalgebra-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kalzium-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kamera-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kanagram-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kapman-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kate-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"katomic-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kblackbox-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kblocks-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kbounce-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kbreakout-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kbruch-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kcalc-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kcharselect-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kcolorchooser-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kde-base-artwork-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kde-baseapps-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kde-l10n-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kde-print-manager-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kde-runtime-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kde-wallpapers-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kde-workspace-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdeaccessibility-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdeadmin-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdeartwork-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdebindings-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdeedu-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdegames-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdegraphics-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdegraphics-mobipocket-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdegraphics-strigi-analyzer-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdegraphics-thumbnailers-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdelibs-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdemultimedia-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdenetwork-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdepim-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdepim-runtime-4.10.4-1.fc19.2")) flag++;
if (rpm_check(release:"FC19", reference:"kdepimlibs-4.10.4-2.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdeplasma-addons-4.10.4-2.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdesdk-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdetoys-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdeutils-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdf-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kdiamond-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kfloppy-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kfourinline-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kgamma-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kgeography-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kgoldrunner-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kgpg-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"khangman-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kig-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kigo-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"killbots-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kimono-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kiriki-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kiten-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kjumpingcube-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"klettres-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"klickety-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"klines-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kmag-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kmahjongg-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kmines-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kmix-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kmousetool-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kmouth-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kmplot-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"knavalbattle-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"knetwalk-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kolf-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kollision-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kolourpaint-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"konquest-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"konsole-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kpat-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kremotecontrol-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kreversi-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kross-interpreters-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kruler-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ksaneplugin-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kscd-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kshisen-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ksirk-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ksnakeduel-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ksnapshot-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kspaceduel-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ksquares-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kstars-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ksudoku-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ktimer-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ktouch-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ktuberling-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kturtle-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kubrick-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kwallet-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"kwordquiz-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkcddb-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkcompactdisc-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkdcraw-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkdeedu-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkdegames-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkexiv2-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkipi-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libkmahjongg-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libksane-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"lskat-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"marble-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nepomuk-core-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nepomuk-widgets-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"okular-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"oxygen-icon-theme-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"pairs-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"palapeli-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"parley-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"picmi-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"pykde4-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"qyoto-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"rocs-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ruby-korundum-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ruby-qt-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"smokegen-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"smokekde-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"smokeqt-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"step-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"superkaramba-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"svgpart-4.10.4-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"sweeper-4.10.4-1.fc19")) flag++;


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
