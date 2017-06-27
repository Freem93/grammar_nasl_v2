#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-10182.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67272);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2013-2120");
  script_bugtraq_id(60216);
  script_xref(name:"FEDORA", value:"2013-10182");

  script_name(english:"Fedora 17 : analitza-4.10.4-1.fc17 / ark-4.10.4-1.fc17 / audiocd-kio-4.10.4-1.fc17 / etc (2013-10182)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109073.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fbae17d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109074.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8aeeba4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?295a733e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42fb259e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64660dca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109078.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edd45f6e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8bfcbbd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109080.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bc57882"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109081.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5287dbd6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109082.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44ccef12"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109083.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26300c34"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeb7f570"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?821da07f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?678ab743"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64b3731b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?325efcfb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc55227a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109090.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f02438ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b722f97"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109092.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98644d73"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2649a95f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109094.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04efcf38"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109095.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c6015c1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109096.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d19f14d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109097.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3ec8bac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109098.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb4c29df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a4013eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d96c3f23"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5874ac34"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcf73d35"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e592b02"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8276cc9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aaadfc9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bde66ff4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109107.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d856e9cf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109108.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64ad135f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25b20058"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109110.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7322c5db"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109111.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5fdf9b7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9fe1a08"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109113.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76ec8996"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109114.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4c27479"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00fc2c60"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ed0c939"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14de7504"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca4085d1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?711db6fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9951c587"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?197d0906"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97347d0d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e84bcba1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc03e4dc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4579de4c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc12d9db"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a16f924d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ebc42f2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcfe5526"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109130.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63f2c34f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7bd0b2a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?428ff4d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?115b0c41"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d26ae14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c527711"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aae7ba39"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f85f9c2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a7944b7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109139.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f79524f0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e29ce78c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7d8fe66"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a1c089a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?168282fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50ba21c6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72dd381f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?793a0e0a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a24ba2f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65396c0f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7732fcc7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?daec2602"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de215801"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5855b76"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109153.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?867b5c24"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd9242fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5654398e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?180a9c85"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e33953b9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109158.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23b98a15"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e1bf9c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f34c1e5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109161.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72454c53"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87348c15"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af80690d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109164.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1626a2ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?279a0bcd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109166.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03a6e7b4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109167.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5ed62ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109168.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0abb92e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109169.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d56229eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?943f363c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02f3da51"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c327c17"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c07bc1ec"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109174.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ca0667a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109175.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de7488cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109176.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1e67d74"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109177.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61f0f84c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6167d4e2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?721783ec"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26ab8bcd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d705fc3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109182.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74e578b8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43fb8f41"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed67e24a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?220bab98"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109186.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfe1ff9a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109187.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ed5fbc2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109188.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0de786eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109189.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b76e0ca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?278afd40"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109191.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f5d2e24"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109192.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8d207ac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109193.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3256be5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aab6bf49"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109195.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?287b5cf2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db586b7b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109197.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?715646bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109198.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90c66175"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67bebd64"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109200.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed6532eb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109201.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0cc562dc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109202.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5889972e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109203.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25e5abd5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109204.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?367d972d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109205.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37c669c8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109206.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db73a68a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109207.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?370621e7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109208.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8fa3168b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdb8d929"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109210.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa4f449a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109211.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdaa879c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109212.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12c05dae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80ed32cb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?489933b2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d3462c3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff9b689c"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"analitza-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ark-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"audiocd-kio-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"blinken-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"bomber-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"bovo-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"cantor-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"dragon-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"filelight-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"granatier-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"gwenview-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"jovie-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"juk-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kaccessible-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kactivities-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kajongg-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kalgebra-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kalzium-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kamera-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kanagram-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kapman-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kate-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"katomic-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kblackbox-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kblocks-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kbounce-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kbreakout-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kbruch-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kcalc-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kcharselect-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kcolorchooser-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-base-artwork-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-baseapps-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-l10n-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-print-manager-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-runtime-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-wallpapers-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kde-workspace-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeaccessibility-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeadmin-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeartwork-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdebindings-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeedu-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegames-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-mobipocket-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-strigi-analyzer-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdegraphics-thumbnailers-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdelibs-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdemultimedia-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdenetwork-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdepim-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdepim-runtime-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdepimlibs-4.10.4-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeplasma-addons-4.10.4-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdesdk-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdetoys-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdeutils-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdf-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kdiamond-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kfloppy-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kfourinline-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgamma-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgeography-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgoldrunner-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kgpg-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"khangman-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kig-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kigo-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"killbots-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kimono-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kiriki-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kiten-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kjumpingcube-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"klettres-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"klickety-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"klines-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmag-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmahjongg-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmines-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmix-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmousetool-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmouth-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kmplot-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"knavalbattle-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"knetwalk-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kolf-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kollision-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kolourpaint-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"konquest-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"konsole-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kpat-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kremotecontrol-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kreversi-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kross-interpreters-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kruler-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksaneplugin-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kscd-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kshisen-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksirk-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksnakeduel-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksnapshot-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kspaceduel-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksquares-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kstars-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ksudoku-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ktimer-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ktouch-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ktuberling-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kturtle-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kubrick-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kwallet-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"kwordquiz-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkcddb-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkcompactdisc-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkdcraw-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkdeedu-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkdegames-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkexiv2-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkipi-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libkmahjongg-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libksane-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"lskat-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"marble-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"nepomuk-core-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"nepomuk-widgets-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"okular-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"oxygen-icon-theme-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"pairs-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"palapeli-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"parley-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"picmi-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"pykde4-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"qyoto-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"rocs-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ruby-korundum-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ruby-qt-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"smokegen-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"smokekde-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"smokeqt-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"step-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"superkaramba-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"svgpart-4.10.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"sweeper-4.10.4-1.fc17")) flag++;


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
